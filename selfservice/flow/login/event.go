// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"context"
	"net/http"
	"time"

	"github.com/gofrs/uuid"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/httpx"
)

// EventType is the kind of login result an Event reports.
type EventType string

// EventResult is the outcome of the login attempt an Event reports.
type EventResult string

const (
	// EventTypeLogin reports the result of a login (first factor, MFA step-up or refresh).
	EventTypeLogin EventType = "login"
	// EventTypeVerified reports a failed verification during login, such as a rejected MFA code.
	EventTypeVerified EventType = "verified"

	// EventDetailMFA is the detail of a verified event caused by a second factor.
	EventDetailMFA = "mfa"

	// EventResultSuccess means the identity logged in and a session was saved.
	EventResultSuccess EventResult = "success"
	// EventResultDenied means the login was rejected, for example because of wrong credentials.
	EventResultDenied EventResult = "denied"
	// EventResultFailure means the login could not be completed because a dependency failed.
	EventResultFailure EventResult = "failure"
)

// Reasons for a failed login.
const (
	ReasonInvalidCredentials  = "invalid_credentials"
	ReasonIdentityDisabled    = "identity_disabled"
	ReasonLDAPUnavailable     = "ldap_unavailable"
	ReasonAuthorizationDenied = "authorization_denied"
)

// Details for a failed login. They are recorded in the event only, the user
// always sees the generic message of the reason.
const (
	ReasonDetailUnknownUser      = "unknown_user"
	ReasonDetailAmbiguousUser    = "ambiguous_user"
	ReasonDetailWrongPassword    = "wrong_password"
	ReasonDetailInvalidCode      = "invalid_code"
	ReasonDetailCodeAlreadyUsed  = "code_already_used"
	ReasonDetailInvalidAssertion = "invalid_assertion"
)

type (
	// Event is the payload sent to the login notification hooks.
	//
	// It never contains a password, a one-time code, a WebAuthn assertion, a
	// session token or a cookie.
	Event struct {
		// EventID is unique per event and stays the same across delivery retries,
		// so the receiver can deduplicate.
		EventID    uuid.UUID `json:"event_id"`
		Type       EventType `json:"type"`
		Detail     string    `json:"detail,omitempty"`
		OccurredAt time.Time `json:"occurred_at"`

		FlowID   uuid.UUID `json:"flow_id"`
		FlowType string    `json:"flow_type"`

		Method       identity.CredentialsType             `json:"method,omitempty"`
		RequestedAAL identity.AuthenticatorAssuranceLevel `json:"requested_aal,omitempty"`
		AAL          identity.AuthenticatorAssuranceLevel `json:"aal,omitempty"`
		IsRefresh    bool                                 `json:"is_refresh"`

		Result       EventResult `json:"result"`
		Reason       string      `json:"reason,omitempty"`
		ReasonDetail string      `json:"reason_detail,omitempty"`

		IdentityID        *uuid.UUID `json:"identity_id"`
		ClaimedIdentifier string     `json:"claimed_identifier,omitempty"`
		SessionID         *uuid.UUID `json:"session_id,omitempty"`

		ClientIP  string `json:"client_ip"`
		UserAgent string `json:"user_agent"`
	}

	// EventNotifier delivers login events. Implementations must not block the
	// caller and must not change the outcome of the login.
	EventNotifier interface {
		NotifyLoginEvent(ctx context.Context, e *Event)
	}

	EventNotifierProvider interface {
		LoginEventNotifiers(ctx context.Context) []EventNotifier
	}

	// Failure describes a failed login that must be reported. Only failures that
	// are recorded with Flow.RecordFailure produce an event.
	Failure struct {
		Type         EventType
		Detail       string
		Result       EventResult
		Reason       string
		ReasonDetail string

		// Method is the method that failed. If empty, the method recorded with
		// RecordClaimedIdentifier or the flow's active method is used.
		Method identity.CredentialsType
		// IdentityID is the identity that tried to log in, if Kratos knows it.
		IdentityID uuid.UUID
		// AAL is the assurance level of the session the identity already has.
		AAL identity.AuthenticatorAssuranceLevel
	}

	// attempt holds what the strategies learned about the current login request.
	// It only lives as long as the request and is never persisted.
	attempt struct {
		method            identity.CredentialsType
		claimedIdentifier string
		failure           *Failure
	}
)

// NewMFAFailure describes a second factor that was rejected during login.
// identityID and aal are those of the session the identity already has.
func NewMFAFailure(method identity.CredentialsType, reasonDetail string, identityID uuid.UUID, aal identity.AuthenticatorAssuranceLevel) Failure {
	return Failure{
		Type:         EventTypeVerified,
		Detail:       EventDetailMFA,
		Result:       EventResultDenied,
		Reason:       ReasonInvalidCredentials,
		ReasonDetail: reasonDetail,
		Method:       method,
		IdentityID:   identityID,
		AAL:          aal,
	}
}

func (f *Flow) loginAttempt() *attempt {
	if f.attempt == nil {
		f.attempt = new(attempt)
	}
	return f.attempt
}

// RecordClaimedIdentifier remembers the identifier the user submitted with
// the given method, so that a failure event (also one raised later by a hook)
// can say who tried to log in.
func (f *Flow) RecordClaimedIdentifier(method identity.CredentialsType, identifier string) {
	if f == nil {
		return
	}
	a := f.loginAttempt()
	a.method = method
	a.claimedIdentifier = identifier
}

// RecordFailure marks the current request as a failed login that has to be
// reported when the error reaches the login error handler.
func (f *Flow) RecordFailure(failure Failure) {
	if f == nil {
		return
	}
	f.loginAttempt().failure = &failure
}

// takeFailure returns the recorded failure and clears it, so that the same
// failure is reported at most once.
func (f *Flow) takeFailure() (failure *Failure, method identity.CredentialsType, claimedIdentifier string) {
	if f == nil || f.attempt == nil {
		return nil, "", ""
	}
	a := f.attempt
	failure, a.failure = a.failure, nil
	return failure, a.method, a.claimedIdentifier
}

func (f *Flow) claimedIdentifier() string {
	if f == nil || f.attempt == nil {
		return ""
	}
	return f.attempt.claimedIdentifier
}

func newEvent(r *http.Request, f *Flow, typ EventType, result EventResult) *Event {
	return &Event{
		EventID:      x.NewUUID(),
		Type:         typ,
		OccurredAt:   time.Now().UTC(),
		FlowID:       f.ID,
		FlowType:     string(f.Type),
		Method:       f.Active,
		RequestedAAL: f.RequestedAAL,
		IsRefresh:    f.Refresh,
		Result:       result,
		ClientIP:     httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
	}
}

// NewSuccessEvent builds the event for a login that saved session s.
func NewSuccessEvent(r *http.Request, f *Flow, s *session.Session) *Event {
	e := newEvent(r, f, EventTypeLogin, EventResultSuccess)
	e.AAL = s.AuthenticatorAssuranceLevel
	e.ClaimedIdentifier = f.claimedIdentifier()
	e.SessionID = nonNilUUID(s.ID)

	// The identity on the session is the one that was saved. For a first LDAP
	// login it is created by the after login web hook, which writes its ID to
	// the session's identity and not to the identity the strategy returned.
	if s.Identity != nil {
		e.IdentityID = nonNilUUID(s.Identity.ID)
	}
	if e.IdentityID == nil {
		e.IdentityID = nonNilUUID(s.IdentityID)
	}
	return e
}

// NewFailureEvent builds the event for a recorded failure.
func NewFailureEvent(r *http.Request, f *Flow, failure *Failure, method identity.CredentialsType, claimedIdentifier string) *Event {
	typ := failure.Type
	if typ == "" {
		typ = EventTypeLogin
	}
	e := newEvent(r, f, typ, failure.Result)
	e.Detail = failure.Detail
	e.Reason = failure.Reason
	e.ReasonDetail = failure.ReasonDetail
	e.AAL = failure.AAL
	e.IdentityID = nonNilUUID(failure.IdentityID)
	e.ClaimedIdentifier = claimedIdentifier
	switch {
	case failure.Method != "":
		e.Method = failure.Method
	case method != "":
		e.Method = method
	}
	return e
}

func nonNilUUID(id uuid.UUID) *uuid.UUID {
	if id.IsNil() {
		return nil
	}
	return &id
}

func notifyLoginEvent(ctx context.Context, d interface {
	EventNotifierProvider
	x.LoggingProvider
}, e *Event,
) {
	notifiers := d.LoginEventNotifiers(ctx)
	if len(notifiers) == 0 {
		return
	}

	d.Logger().
		WithField("event_id", e.EventID).
		WithField("event_type", e.Type).
		WithField("event_result", e.Result).
		WithField("event_reason", e.Reason).
		Debug("Dispatching login event.")

	// The notifiers deliver asynchronously and never fail the login.
	for _, n := range notifiers {
		n.NotifyLoginEvent(ctx, e)
	}
}
