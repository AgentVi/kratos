# Login Result Notifications

Kratos can tell another service about every login result, so that it can
write an audit log. Successful and failed
logins are sent to the hooks under `selfservice.flows.login.notifications`.

Unlike the `before` and `after` login hooks, a notification hook:

- runs after the session was saved (success) or after the login failed,
- delivers in the background and ignores the response,
- can never change an identity or stop a login,
- never delays a login, even if the receiver is slow or down.

## Configuration

```yaml
selfservice:
  flows:
    login:
      notifications:
        workers: 8                    # default
        queue_size: 1000              # default
        hooks:
          - hook: web_hook
            config:
              url: http://audit-receiver.internal.example/login-events
              method: POST            # default
              headers:                # optional
                X-Source: kratos
              body: file:///etc/config/kratos/login_event.jsonnet # optional
              max_retries: 2          # default, 0 to 10
```

`web_hook` is the only hook type. `url`, `method`, `headers`, `auth` and
`body` work as for the regular `web_hook`. The Jsonnet template receives the
event below as `ctx`. Without a `body`, the event is sent as JSON as it is.

Without an `auth` option, the request carries no credential. Set one
(`api_key` in a header or cookie, or `basic_auth`, as for the regular
`web_hook`) if the receiver checks one.

The hook list takes effect without a restart. `workers` and `queue_size` are
read once, when the first login event is sent, so changing them needs a
restart.

### Delivery

Kratos delivers the events through a fixed number of workers (`workers`) that
take them from a queue of fixed size (`queue_size`). Every notification hook
shares the workers and the queue, and an event for several hooks is one
delivery per hook. A login only puts its event in the queue and never waits
for a delivery. The workers start with the first login event that has a hook
to go to, so Kratos without notification hooks starts none.

A delivery is retried after a network error or a 5xx response, with the same
`event_id` and an `Idempotency-Key` header that holds it. A delivery takes at
most two minutes, including its retries. The two minutes start when a worker
takes the event, so time spent waiting in the queue does not count.

Delivery is best effort. An event is lost:

- when the queue is full, because every worker is busy and `queue_size`
  events wait already. The event is dropped at once, and the login goes on;
- when the receiver is down for longer than the retries last;
- when Kratos stops, together with every event that waits in the queue.

Each lost event, apart from those lost when Kratos stops, logs the same
warning with its `event_id` and `event_type`:

```text
level=warning msg="Could not deliver the login event." error=... event_id=... event_type=...
```

An alert on this message covers both a dropped event and a delivery that gave
up. The `error` field tells them apart: `the login event queue is full` for a
dropped event.

The HTTP client is the one the web hooks use, so
`clients.http.disallow_private_ip_ranges` applies.

## Event

```json
{
  "event_id": "0b4ac4b5-0a83-4a7e-8f0c-7a6d0d6b6c3e",
  "type": "login",
  "occurred_at": "2026-11-05T12:00:00Z",
  "flow_id": "5e0b8f39-0e0b-4f4c-9d70-0b5fa3c55d0d",
  "flow_type": "browser",
  "method": "ldap",
  "requested_aal": "aal1",
  "aal": "aal1",
  "is_refresh": false,
  "result": "success",
  "identity_id": "c8a5a7a8-1b9b-4c47-8f9b-0d8b6e1c2f11",
  "claimed_identifier": "alice",
  "session_id": "8c1d0b7e-9d2a-4f0e-b5c3-2a9e6d1f4b7a",
  "client_ip": "192.0.2.10",
  "user_agent": "Mozilla/5.0 ..."
}
```

| Field | Description |
| --- | --- |
| `event_id` | Unique per event, the same for every retry. |
| `type` | `login`, or `verified` for a failed MFA check. |
| `detail` | `mfa` for a `verified` event. |
| `occurred_at` | When Kratos saw the result (UTC). |
| `flow_id`, `flow_type` | The login flow, `api` or `browser` (SPA flows are `browser`). |
| `method` | `password`, `ldap`, `totp`, `lookup_secret`, `webauthn`, ... |
| `requested_aal` | The AAL the flow asked for. |
| `aal` | Success: the AAL the session reached. MFA failure: the AAL of the existing session. Empty for a first factor failure. |
| `is_refresh` | Whether the flow was a re-authentication. |
| `result` | `success`, `denied` (the login was rejected) or `failure` (Kratos could not decide). |
| `reason`, `reason_detail` | Why a login failed, see below. |
| `identity_id` | The identity, or `null` if Kratos does not know one. |
| `claimed_identifier` | The identifier the user typed (password and LDAP). |
| `session_id` | The saved session, on success only. |
| `client_ip` | `httpx.ClientIP`, as stored for session devices: `True-Client-IP`, then `X-Forwarded-For`, then the remote address (including the port). |
| `user_agent` | The `User-Agent` header. |

The event never contains a password, a TOTP or lookup code, a WebAuthn
assertion, a session token or a cookie.

A first-factor login, an MFA step-up and a re-authentication all produce a
`login` success event. Use `aal`, `requested_aal` and `is_refresh` to tell
them apart.

### Failures

Only these failures produce an event:

| `type` | `result` | `reason` | `reason_detail` | When |
| --- | --- | --- | --- | --- |
| `login` | `denied` | `invalid_credentials` | `unknown_user` | Password: no identity has the identifier. LDAP: the directory has no such user. |
| `login` | `denied` | `invalid_credentials` | `ambiguous_user` | LDAP: several directory entries match the username, also across search bases. |
| `login` | `denied` | `invalid_credentials` | `wrong_password` | Password or LDAP: the password is wrong. |
| `login` | `denied` | `identity_disabled` | | The identity is not active. |
| `login` | `failure` | `ldap_unavailable` | | LDAP: dial, LDAPS or StartTLS handshake, service bind, user or group search failed. |
| `login` | `denied` | `authorization_denied` | | An `after` login hook rejected the login, for example an `after` web hook with `response.parse`. |
| `verified` (`detail: mfa`) | `denied` | `invalid_credentials` | `invalid_code` | TOTP code or lookup code is wrong. |
| `verified` (`detail: mfa`) | `denied` | `invalid_credentials` | `code_already_used` | The lookup code was used before. |
| `verified` (`detail: mfa`) | `denied` | `invalid_credentials` | `invalid_assertion` | The WebAuthn second factor was rejected. |

The user always sees the same generic message for the `invalid_credentials`
cases, `reason_detail` is only in the event.

Expired flows, CSRF failures, invalid payloads, "already logged in",
configuration problems and internal errors produce no event.

`identity_id` of a failure:

- Password, wrong password: the identity that has the identifier.
- LDAP: the identity whose LDAP credentials have the identifier, looked up in
  Kratos, also when the directory is unavailable. `null` if there is none,
  for example before the first successful login.
- Disabled identity, hook rejection and MFA: the identity that logged in.

If an `after` web hook creates the identity on a first LDAP login, the
success event carries the ID of that saved identity.

## How it works

- `selfservice/flow/login/event.go`: the event, the `EventNotifier` interface
  and the per-request login attempt. Strategies call
  `Flow.RecordClaimedIdentifier` and `Flow.RecordFailure` on the login flow.
  The attempt lives on the flow object of the request and is never persisted.
- `selfservice/flow/login/hook.go`: `PostLoginHook` sends the success event
  after `UpsertSession` (API) or `UpsertAndIssueCookie` (browser and SPA), and
  records `identity_disabled` and `authorization_denied`.
- `selfservice/flow/login/error.go`: `WriteFlowError` sends the recorded
  failure. Taking the failure clears it, so it is sent at most once, also
  when the handler recurses for an expired flow.
- `selfservice/hook/login_event_web_hook.go`: the `web_hook` notifier. It
  queues the delivery, or logs the warning if the queue is full.
- `selfservice/hook/login_event_dispatcher.go`: the queue and the workers.
- `driver/registry_default_login.go`: `LoginEventNotifiers` builds the
  notifiers from the configuration on every call, so changes are picked up
  without a restart. `LoginEventDispatcher` creates the one dispatcher of the
  process on its first call.

## Testing

```sh
go test -tags sqlite ./selfservice/flow/login/ -run 'Event|Failure'
go test -tags sqlite ./selfservice/hook/ -run 'TestLoginEvent'
go test -tags sqlite ./selfservice/strategy/password/ -run TestLoginEvents
go test -tags sqlite ./selfservice/strategy/ldap/
go test -tags sqlite ./selfservice/strategy/totp/ -run TestTOTPLoginEvents
go test -tags sqlite ./selfservice/strategy/lookup/ -run TestLookupLoginEvents
go test -tags sqlite ./selfservice/strategy/webauthn/ -run TestWebAuthnLoginEvents
```

`internal/testhelpers.NewLoginEventReceiver` starts a receiver and configures
it as the notification hook.

## Decisions

- Delivery is best effort, with retries and no database outbox. Events can be
  lost when the queue is full or Kratos stops, as described under
  [Delivery](#delivery).
- Kratos reports `authorization_denied` when an `after` hook rejects a login,
  so the hook itself need not report it.
- Kratos sends `client_ip`. Whether to store it is up to the receiver.
