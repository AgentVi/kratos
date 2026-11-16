// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package hook_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/hook"
	"github.com/ory/kratos/x"
)

type receivedRequest struct {
	method  string
	headers http.Header
	body    []byte
}

func newLoginEvent() *login.Event {
	identityID := x.NewUUID()
	return &login.Event{
		EventID:           x.NewUUID(),
		Type:              login.EventTypeLogin,
		OccurredAt:        time.Now().UTC(),
		FlowID:            x.NewUUID(),
		FlowType:          "browser",
		Method:            identity.CredentialsTypePassword,
		RequestedAAL:      identity.AuthenticatorAssuranceLevel1,
		Result:            login.EventResultDenied,
		Reason:            login.ReasonInvalidCredentials,
		ReasonDetail:      login.ReasonDetailWrongPassword,
		IdentityID:        &identityID,
		ClaimedIdentifier: "alice",
		ClientIP:          "192.0.2.10",
		UserAgent:         "test-agent",
	}
}

func TestLoginEventWebHook(t *testing.T) {
	_, reg := internal.NewFastRegistryWithMocks(t)

	newReceiver := func(t *testing.T, handle func(w http.ResponseWriter, attempt int64)) (*httptest.Server, chan receivedRequest) {
		received := make(chan receivedRequest, 10)
		var attempts int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			received <- receivedRequest{method: r.Method, headers: r.Header.Clone(), body: body}
			if handle != nil {
				handle(w, atomic.AddInt64(&attempts, 1))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(ts.Close)
		return ts, received
	}

	next := func(t *testing.T, received chan receivedRequest) receivedRequest {
		t.Helper()
		select {
		case r := <-received:
			return r
		case <-time.After(10 * time.Second):
			require.FailNow(t, "the web hook received nothing")
			return receivedRequest{}
		}
	}

	t.Run("case=sends the event as JSON with POST by default", func(t *testing.T) {
		ts, received := newReceiver(t, nil)
		e := newLoginEvent()

		hook.NewLoginEventWebHook(reg, json.RawMessage(fmt.Sprintf(`{"url":%q}`, ts.URL))).NotifyLoginEvent(context.Background(), e)

		r := next(t, received)
		assert.Equal(t, http.MethodPost, r.method)
		assert.Equal(t, "application/json", r.headers.Get("Content-Type"))
		assert.Equal(t, e.EventID.String(), r.headers.Get("Idempotency-Key"))

		var got login.Event
		require.NoError(t, json.Unmarshal(r.body, &got))
		assert.Equal(t, e.EventID, got.EventID)
		assert.Equal(t, e.Type, got.Type)
		assert.Equal(t, e.Result, got.Result)
		assert.Equal(t, e.Reason, got.Reason)
		assert.Equal(t, e.ReasonDetail, got.ReasonDetail)
		assert.Equal(t, e.IdentityID, got.IdentityID)
		assert.Equal(t, e.ClaimedIdentifier, got.ClaimedIdentifier)
		assert.Equal(t, e.ClientIP, got.ClientIP)
		assert.Equal(t, e.UserAgent, got.UserAgent)
		assert.Equal(t, e.FlowID, got.FlowID)
		assert.Equal(t, e.Method, got.Method)
	})

	t.Run("case=uses the configured auth, headers and body", func(t *testing.T) {
		ts, received := newReceiver(t, nil)
		e := newLoginEvent()
		body := base64.StdEncoding.EncodeToString([]byte(`function(ctx) { id: ctx.event_id, who: ctx.claimed_identifier, outcome: ctx.result }`))
		conf := fmt.Sprintf(`{
			"url": %q,
			"method": "PUT",
			"body": "base64://%s",
			"headers": {"X-Source": "kratos"},
			"auth": {"type": "api_key", "config": {"name": "X-API-Key", "value": "the-api-key", "in": "header"}}
		}`, ts.URL, body)

		hook.NewLoginEventWebHook(reg, json.RawMessage(conf)).NotifyLoginEvent(context.Background(), e)

		r := next(t, received)
		assert.Equal(t, http.MethodPut, r.method)
		assert.Equal(t, "the-api-key", r.headers.Get("X-API-Key"))
		assert.Equal(t, "kratos", r.headers.Get("X-Source"))
		assert.Equal(t, e.EventID.String(), gjson.GetBytes(r.body, "id").String())
		assert.Equal(t, "alice", gjson.GetBytes(r.body, "who").String())
		assert.Equal(t, "denied", gjson.GetBytes(r.body, "outcome").String())
	})

	t.Run("case=retries a failed delivery with the same event ID", func(t *testing.T) {
		ts, received := newReceiver(t, func(w http.ResponseWriter, attempt int64) {
			if attempt == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		e := newLoginEvent()

		hook.NewLoginEventWebHook(reg, json.RawMessage(fmt.Sprintf(`{"url":%q,"max_retries":1}`, ts.URL))).NotifyLoginEvent(context.Background(), e)

		first, second := next(t, received), next(t, received)
		assert.Equal(t, e.EventID.String(), gjson.GetBytes(first.body, "event_id").String())
		assert.Equal(t, e.EventID.String(), gjson.GetBytes(second.body, "event_id").String())
		assert.Equal(t, first.headers.Get("Idempotency-Key"), second.headers.Get("Idempotency-Key"))
	})

	t.Run("case=does not retry when retries are disabled", func(t *testing.T) {
		ts, received := newReceiver(t, func(w http.ResponseWriter, _ int64) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		hook.NewLoginEventWebHook(reg, json.RawMessage(fmt.Sprintf(`{"url":%q,"max_retries":0}`, ts.URL))).NotifyLoginEvent(context.Background(), newLoginEvent())

		next(t, received)
		select {
		case <-received:
			assert.Fail(t, "the delivery was retried")
		case <-time.After(2 * time.Second):
		}
	})

	t.Run("case=a slow receiver does not block the caller", func(t *testing.T) {
		release := make(chan struct{})
		ts, received := newReceiver(t, func(w http.ResponseWriter, _ int64) {
			<-release
			w.WriteHeader(http.StatusNoContent)
		})
		// Registered after the server's cleanup so that it runs first: closing
		// the server waits for the blocked handler.
		t.Cleanup(func() { close(release) })

		start := time.Now()
		hook.NewLoginEventWebHook(reg, json.RawMessage(fmt.Sprintf(`{"url":%q}`, ts.URL))).NotifyLoginEvent(context.Background(), newLoginEvent())
		assert.Less(t, time.Since(start), 500*time.Millisecond)

		next(t, received)
	})

	t.Run("case=delivers after the request context was canceled", func(t *testing.T) {
		ts, received := newReceiver(t, nil)
		ctx, cancel := context.WithCancel(context.Background())
		e := newLoginEvent()

		hook.NewLoginEventWebHook(reg, json.RawMessage(fmt.Sprintf(`{"url":%q}`, ts.URL))).NotifyLoginEvent(ctx, e)
		cancel()

		r := next(t, received)
		assert.Equal(t, e.EventID.String(), gjson.GetBytes(r.body, "event_id").String())
	})

	t.Run("case=an unreachable receiver does not panic or block", func(t *testing.T) {
		start := time.Now()
		hook.NewLoginEventWebHook(reg, json.RawMessage(`{"url":"http://127.0.0.1:1","max_retries":0}`)).NotifyLoginEvent(context.Background(), newLoginEvent())
		assert.Less(t, time.Since(start), 500*time.Millisecond)
	})

	t.Run("case=null identity is sent as null", func(t *testing.T) {
		ts, received := newReceiver(t, nil)
		e := newLoginEvent()
		e.IdentityID = nil

		hook.NewLoginEventWebHook(reg, json.RawMessage(fmt.Sprintf(`{"url":%q}`, ts.URL))).NotifyLoginEvent(context.Background(), e)

		r := next(t, received)
		require.True(t, gjson.GetBytes(r.body, "identity_id").Exists(), "%s", r.body)
		assert.Equal(t, gjson.Null, gjson.GetBytes(r.body, "identity_id").Type)
		assert.False(t, gjson.GetBytes(r.body, "session_id").Exists())
	})
}
