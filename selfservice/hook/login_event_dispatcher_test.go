// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package hook_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/selfservice/hook"
	"github.com/ory/x/logrusx"
)

// dispatcherDeps replaces the registry's logger and shared dispatcher.
type dispatcherDeps struct {
	*driver.RegistryDefault
	l *logrusx.Logger
	d *hook.LoginEventDispatcher
}

func (d dispatcherDeps) Logger() *logrusx.Logger { return d.l }

func (d dispatcherDeps) LoginEventDispatcher(context.Context) *hook.LoginEventDispatcher {
	return d.d
}

// blockingReceiver holds every request until it is released.
type blockingReceiver struct {
	URL      string
	received chan []byte
	inFlight atomic.Int64
	maxSeen  atomic.Int64
	release  func()
}

func newBlockingReceiver(t *testing.T) *blockingReceiver {
	r := &blockingReceiver{received: make(chan []byte, 100)}
	released := make(chan struct{})
	var once sync.Once
	r.release = func() { once.Do(func() { close(released) }) }

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := r.inFlight.Add(1)
		defer r.inFlight.Add(-1)
		for {
			m := r.maxSeen.Load()
			if n <= m || r.maxSeen.CompareAndSwap(m, n) {
				break
			}
		}
		body, _ := io.ReadAll(req.Body)
		r.received <- body
		<-released
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	// Registered after the server's cleanup so that it runs first: closing
	// the server waits for the blocked handlers.
	t.Cleanup(r.release)
	r.URL = ts.URL
	return r
}

func (r *blockingReceiver) next(t *testing.T) []byte {
	t.Helper()
	select {
	case b := <-r.received:
		return b
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the web hook received nothing")
		return nil
	}
}

func (r *blockingReceiver) assertNone(t *testing.T) {
	t.Helper()
	select {
	case b := <-r.received:
		assert.Fail(t, "unexpected delivery", "%s", b)
	case <-time.After(300 * time.Millisecond):
	}
}

func webHookConf(url string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"url":%q,"max_retries":0}`, url))
}

func TestLoginEventDispatcher(t *testing.T) {
	_, reg := internal.NewFastRegistryWithMocks(t)

	newDeps := func(t *testing.T, workers, queueSize int) (dispatcherDeps, *logtest.Hook) {
		l := logrusx.New("kratos", "test")
		logs := logtest.NewLocal(l.Logger)
		return dispatcherDeps{RegistryDefault: reg, l: l, d: hook.NewLoginEventDispatcher(workers, queueSize)}, logs
	}

	deliveryWarnings := func(logs *logtest.Hook) map[string]string {
		got := map[string]string{}
		for _, e := range logs.AllEntries() {
			if e.Level == logrus.WarnLevel && e.Message == "Could not deliver the login event." {
				got[fmt.Sprint(e.Data["event_id"])] = fmt.Sprint(e.Data["error"])
			}
		}
		return got
	}

	t.Run("case=runs no more deliveries at once than there are workers", func(t *testing.T) {
		receiver := newBlockingReceiver(t)
		deps, _ := newDeps(t, 2, 10)
		h := hook.NewLoginEventWebHook(deps, webHookConf(receiver.URL))

		for i := 0; i < 5; i++ {
			h.NotifyLoginEvent(context.Background(), newLoginEvent())
		}

		receiver.next(t)
		receiver.next(t)
		receiver.assertNone(t)
		assert.EqualValues(t, 2, receiver.inFlight.Load())

		receiver.release()
		for i := 0; i < 3; i++ {
			receiver.next(t)
		}
		assert.EqualValues(t, 2, receiver.maxSeen.Load())
	})

	t.Run("case=drops the event and logs a warning when the queue is full", func(t *testing.T) {
		receiver := newBlockingReceiver(t)
		deps, logs := newDeps(t, 1, 1)
		h := hook.NewLoginEventWebHook(deps, webHookConf(receiver.URL))

		inFlight, queued, dropped := newLoginEvent(), newLoginEvent(), newLoginEvent()
		h.NotifyLoginEvent(context.Background(), inFlight)
		receiver.next(t) // The only worker is busy now.
		h.NotifyLoginEvent(context.Background(), queued)

		start := time.Now()
		h.NotifyLoginEvent(context.Background(), dropped)
		assert.Less(t, time.Since(start), 100*time.Millisecond)

		warnings := deliveryWarnings(logs)
		require.Contains(t, warnings, dropped.EventID.String())
		assert.Contains(t, warnings[dropped.EventID.String()], hook.ErrLoginEventQueueFull.Error())
		assert.Len(t, warnings, 1)

		receiver.release()
		assert.Equal(t, queued.EventID.String(), gjson.GetBytes(receiver.next(t), "event_id").String())
		receiver.assertNone(t)
	})

	t.Run("case=a job waits in the queue without losing any of its timeout", func(t *testing.T) {
		const timeout = time.Minute
		d := hook.NewLoginEventDispatcherWithTimeout(1, 1, timeout)

		busy, release := make(chan struct{}), make(chan struct{})
		require.True(t, d.Enqueue(context.Background(), func(context.Context) {
			close(busy)
			<-release
		}))
		<-busy // The only worker is busy now.

		started := make(chan time.Time, 1)
		deadline := make(chan time.Time, 1)
		require.True(t, d.Enqueue(context.Background(), func(ctx context.Context) {
			started <- time.Now()
			dl, _ := ctx.Deadline()
			deadline <- dl
		}))

		time.Sleep(200 * time.Millisecond)
		close(release)

		start := <-started
		assert.WithinDuration(t, start.Add(timeout), <-deadline, 50*time.Millisecond)
	})

	t.Run("case=a job does not inherit the request's cancellation", func(t *testing.T) {
		d := hook.NewLoginEventDispatcher(1, 1)
		type key struct{}
		ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "value"))
		cancel()

		done := make(chan error, 1)
		require.True(t, d.Enqueue(ctx, func(ctx context.Context) {
			assert.Equal(t, "value", ctx.Value(key{}))
			done <- ctx.Err()
		}))
		assert.NoError(t, <-done)
	})
}

func TestLoginEventDispatcherRegistry(t *testing.T) {
	ctx := context.Background()

	setHooks := func(t *testing.T, conf *config.Config, urls ...string) {
		hooks := make([]map[string]interface{}, 0, len(urls))
		for _, u := range urls {
			hooks = append(hooks, map[string]interface{}{
				"hook":   "web_hook",
				"config": map[string]interface{}{"url": u, "max_retries": 0},
			})
		}
		conf.MustSet(ctx, config.ViperKeySelfServiceLoginNotificationHooks, hooks)
	}

	notify := func(reg *driver.RegistryDefault) {
		e := newLoginEvent()
		for _, n := range reg.LoginEventNotifiers(ctx) {
			n.NotifyLoginEvent(ctx, e)
		}
	}

	t.Run("case=uses the configured sizes", func(t *testing.T) {
		conf, reg := internal.NewFastRegistryWithMocks(t)
		l := logrusx.New("kratos", "test")
		logs := logtest.NewLocal(l.Logger)
		reg.WithLogger(l)
		conf.MustSet(ctx, config.ViperKeySelfServiceLoginNotificationWorkers, 1)
		conf.MustSet(ctx, config.ViperKeySelfServiceLoginNotificationQueueSize, 1)
		receiver := newBlockingReceiver(t)
		setHooks(t, conf, receiver.URL)

		notify(reg)
		receiver.next(t) // The only worker is busy now.
		notify(reg)      // Queued.
		notify(reg)      // Dropped.

		var drops int
		for _, e := range logs.AllEntries() {
			if strings.Contains(fmt.Sprint(e.Data["error"]), hook.ErrLoginEventQueueFull.Error()) {
				drops++
			}
		}
		assert.Equal(t, 1, drops)

		receiver.release()
		receiver.next(t)
		receiver.assertNone(t)
	})

	t.Run("case=concurrent callers share one dispatcher", func(t *testing.T) {
		_, reg := internal.NewFastRegistryWithMocks(t)

		var wg sync.WaitGroup
		got := make([]*hook.LoginEventDispatcher, 10)
		for i := range got {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				got[i] = reg.LoginEventDispatcher(ctx)
			}(i)
		}
		wg.Wait()
		for _, d := range got {
			assert.Same(t, got[0], d)
		}
	})

	t.Run("case=defaults to 8 workers and a queue of 1000", func(t *testing.T) {
		conf, _ := internal.NewFastRegistryWithMocks(t)
		assert.Equal(t, 8, conf.SelfServiceFlowLoginNotificationWorkers(ctx))
		assert.Equal(t, 1000, conf.SelfServiceFlowLoginNotificationQueueSize(ctx))
	})

	t.Run("case=an event for two hooks reaches both once", func(t *testing.T) {
		conf, reg := internal.NewFastRegistryWithMocks(t)
		a, b := newBlockingReceiver(t), newBlockingReceiver(t)
		a.release()
		b.release()
		setHooks(t, conf, a.URL, b.URL)

		notify(reg)

		assert.Equal(t, gjson.GetBytes(a.next(t), "event_id").String(), gjson.GetBytes(b.next(t), "event_id").String())
		a.assertNone(t)
		b.assertNone(t)
	})

	t.Run("case=a hook added to the configuration receives the next event", func(t *testing.T) {
		conf, reg := internal.NewFastRegistryWithMocks(t)
		a, b := newBlockingReceiver(t), newBlockingReceiver(t)
		a.release()
		b.release()

		setHooks(t, conf, a.URL)
		notify(reg)
		a.next(t)
		b.assertNone(t)

		setHooks(t, conf, a.URL, b.URL)
		notify(reg)
		a.next(t)
		b.next(t)
	})
}
