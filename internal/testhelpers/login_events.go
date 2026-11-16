// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package testhelpers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/flow/login"
)

// ReceivedLoginEvent is a login event as a login notification web hook received it.
type ReceivedLoginEvent struct {
	login.Event
	Raw     []byte
	Headers http.Header
}

// LoginEventReceiver is a web hook that collects login events.
type LoginEventReceiver struct {
	URL    string
	events chan ReceivedLoginEvent
}

// NewLoginEventReceiver starts a web hook and configures it as the only login
// notification hook.
func NewLoginEventReceiver(t *testing.T, conf *config.Config) *LoginEventReceiver {
	r := &LoginEventReceiver{events: make(chan ReceivedLoginEvent, 100)}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var e login.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.events <- ReceivedLoginEvent{Event: e, Raw: raw, Headers: req.Header.Clone()}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	r.URL = ts.URL

	conf.MustSet(context.Background(), config.ViperKeySelfServiceLoginNotificationHooks, []map[string]interface{}{{
		"hook":   "web_hook",
		"config": map[string]interface{}{"url": ts.URL, "max_retries": 0},
	}})
	t.Cleanup(func() {
		conf.MustSet(context.Background(), config.ViperKeySelfServiceLoginNotificationHooks, nil)
	})

	return r
}

// Next waits for the next login event.
func (r *LoginEventReceiver) Next(t *testing.T) ReceivedLoginEvent {
	t.Helper()
	select {
	case e := <-r.events:
		return e
	case <-time.After(10 * time.Second):
		require.FailNow(t, "no login event was received")
		return ReceivedLoginEvent{}
	}
}

// AssertNone checks that no login event arrives for a while.
func (r *LoginEventReceiver) AssertNone(t *testing.T) {
	t.Helper()
	select {
	case e := <-r.events:
		require.FailNow(t, "unexpected login event", "%s", e.Raw)
	case <-time.After(500 * time.Millisecond):
	}
}

// Drain discards the events received so far.
func (r *LoginEventReceiver) Drain() {
	for {
		select {
		case <-r.events:
		case <-time.After(200 * time.Millisecond):
			return
		}
	}
}
