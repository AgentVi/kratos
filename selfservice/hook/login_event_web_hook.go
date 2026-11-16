// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.11.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/kratos/request"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/x/otelx"
)

const (
	// loginEventDefaultBody sends the event as it is.
	loginEventDefaultBody = "function(ctx) ctx"
	// loginEventDefaultMaxRetries matches the retries of the regular web hooks.
	loginEventDefaultMaxRetries = 2
	// loginEventTimeout bounds a delivery including all retries.
	loginEventTimeout = 2 * time.Minute
)

var _ login.EventNotifier = (*LoginEventWebHook)(nil)

type loginEventWebHookDependencies interface {
	webHookDependencies
	LoginEventDispatcherProvider
}

// LoginEventWebHook sends login events to a web hook.
//
// It is configured like the web_hook hook (url, method, headers, auth and a
// Jsonnet body that receives the event as `ctx`), but it only notifies: it
// delivers in the background, ignores the response and can never change an
// identity or stop a login.
type LoginEventWebHook struct {
	deps loginEventWebHookDependencies
	conf json.RawMessage
}

func NewLoginEventWebHook(deps loginEventWebHookDependencies, conf json.RawMessage) *LoginEventWebHook {
	return &LoginEventWebHook{deps: deps, conf: conf}
}

// NotifyLoginEvent queues the delivery of e and returns right away. If the
// queue is full, it drops e and logs the same warning as for a delivery that
// gave up.
func (h *LoginEventWebHook) NotifyLoginEvent(ctx context.Context, e *login.Event) {
	// The delivery outlives the request, which ends as soon as the login
	// response is written. The dispatcher keeps the request's values, which
	// the configuration and tracing need, but not its cancellation.
	queued := h.deps.LoginEventDispatcher(ctx).Enqueue(ctx, func(ctx context.Context) {
		if err := h.deliver(ctx, e); err != nil {
			h.logDeliveryFailure(e, err)
		}
	})
	if !queued {
		h.logDeliveryFailure(e, ErrLoginEventQueueFull)
	}
}

func (h *LoginEventWebHook) logDeliveryFailure(e *login.Event, err error) {
	h.deps.Logger().
		WithError(err).
		WithField("event_id", e.EventID).
		WithField("event_type", e.Type).
		Warn("Could not deliver the login event.")
}

func (h *LoginEventWebHook) deliver(ctx context.Context, e *login.Event) (err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("kratos-webhooks").Start(ctx, "selfservice.hook.LoginEventWebHook.deliver")
	defer otelx.End(span, &err)
	span.SetAttributes(
		attribute.String("login_event.id", e.EventID.String()),
		attribute.String("login_event.type", string(e.Type)),
		attribute.String("login_event.result", string(e.Result)),
	)

	conf, err := h.requestConfig()
	if err != nil {
		return err
	}

	builder, err := request.NewBuilder(ctx, conf, h.deps, jsonnetCache)
	if err != nil {
		return err
	}

	req, err := builder.BuildRequest(ctx, e)
	if errors.Is(err, request.ErrCancel) {
		span.SetAttributes(attribute.Bool("webhook.jsonnet.canceled", true))
		return nil
	} else if err != nil {
		return err
	}
	// Lets the receiver deduplicate deliveries that were retried.
	req.Header.Set("Idempotency-Key", e.EventID.String())

	client := h.deps.HTTPClient(ctx)
	client.RetryMax = h.maxRetries()

	start := time.Now()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return errors.WithStack(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	span.SetAttributes(semconv.HTTPAttributesFromHTTPStatusCode(resp.StatusCode)...)

	if resp.StatusCode >= http.StatusBadRequest {
		return errors.Errorf("login event web hook responded with status code %d", resp.StatusCode)
	}

	h.deps.Logger().
		WithField("event_id", e.EventID).
		WithField("duration", time.Since(start)).
		Debug("Delivered the login event.")
	return nil
}

// requestConfig returns the web hook configuration with the defaults for a
// login event: POST with the event as JSON body.
func (h *LoginEventWebHook) requestConfig() (json.RawMessage, error) {
	conf := []byte(h.conf)
	var err error
	if !gjson.GetBytes(conf, "method").Exists() {
		if conf, err = sjson.SetBytes(conf, "method", http.MethodPost); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	if !gjson.GetBytes(conf, "body").Exists() {
		body := fmt.Sprintf("base64://%s", base64.StdEncoding.EncodeToString([]byte(loginEventDefaultBody)))
		if conf, err = sjson.SetBytes(conf, "body", body); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return conf, nil
}

func (h *LoginEventWebHook) maxRetries() int {
	if v := gjson.GetBytes(h.conf, "max_retries"); v.Exists() && v.Int() >= 0 {
		return int(v.Int())
	}
	return loginEventDefaultMaxRetries
}
