// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"encoding/json"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

func newEventTestFlow() *Flow {
	return &Flow{
		ID:           x.NewUUID(),
		Type:         flow.TypeBrowser,
		RequestedAAL: identity.AuthenticatorAssuranceLevel2,
		Refresh:      true,
		Active:       identity.CredentialsTypeTOTP,
	}
}

func TestRecordedFailureIsTakenOnce(t *testing.T) {
	f := newEventTestFlow()
	f.RecordClaimedIdentifier(identity.CredentialsTypeLDAP, "alice")
	f.RecordFailure(Failure{Result: EventResultDenied, Reason: ReasonInvalidCredentials})

	failure, method, claimed := f.takeFailure()
	require.NotNil(t, failure)
	assert.Equal(t, ReasonInvalidCredentials, failure.Reason)
	assert.Equal(t, identity.CredentialsTypeLDAP, method)
	assert.Equal(t, "alice", claimed)

	failure, _, _ = f.takeFailure()
	assert.Nil(t, failure, "a failure must only be reported once")

	// The claimed identifier stays for a later success event.
	assert.Equal(t, "alice", f.claimedIdentifier())
}

func TestNoFailureRecorded(t *testing.T) {
	failure, _, _ := newEventTestFlow().takeFailure()
	assert.Nil(t, failure)

	var nilFlow *Flow
	nilFlow.RecordFailure(Failure{})
	nilFlow.RecordClaimedIdentifier(identity.CredentialsTypePassword, "alice")
	failure, _, _ = nilFlow.takeFailure()
	assert.Nil(t, failure)
}

func TestNewSuccessEvent(t *testing.T) {
	r := httptest.NewRequest("POST", "/self-service/login", nil)
	r.Header.Set("User-Agent", "test-agent")
	r.Header.Set("X-Forwarded-For", "192.0.2.10")

	t.Run("case=uses the identity saved with the session", func(t *testing.T) {
		// On a first LDAP login the after login web hook creates the identity
		// and writes its ID to the session's identity only.
		f := newEventTestFlow()
		f.RecordClaimedIdentifier(identity.CredentialsTypeLDAP, "alice")
		saved := x.NewUUID()
		s := &session.Session{
			ID:                          x.NewUUID(),
			Identity:                    &identity.Identity{ID: saved},
			AuthenticatorAssuranceLevel: identity.AuthenticatorAssuranceLevel2,
		}

		e := NewSuccessEvent(r, f, s)
		assert.NotEqual(t, uuid.Nil, e.EventID)
		assert.Equal(t, EventTypeLogin, e.Type)
		assert.Equal(t, EventResultSuccess, e.Result)
		require.NotNil(t, e.IdentityID)
		assert.Equal(t, saved, *e.IdentityID)
		require.NotNil(t, e.SessionID)
		assert.Equal(t, s.ID, *e.SessionID)
		assert.Equal(t, identity.AuthenticatorAssuranceLevel2, e.AAL)
		assert.Equal(t, identity.AuthenticatorAssuranceLevel2, e.RequestedAAL)
		assert.True(t, e.IsRefresh)
		assert.Equal(t, f.ID, e.FlowID)
		assert.Equal(t, "browser", e.FlowType)
		assert.Equal(t, identity.CredentialsTypeTOTP, e.Method)
		assert.Equal(t, "alice", e.ClaimedIdentifier)
		assert.Equal(t, "192.0.2.10", e.ClientIP)
		assert.Equal(t, "test-agent", e.UserAgent)
	})

	t.Run("case=falls back to the session's identity ID", func(t *testing.T) {
		id := x.NewUUID()
		e := NewSuccessEvent(r, newEventTestFlow(), &session.Session{ID: x.NewUUID(), IdentityID: id})
		require.NotNil(t, e.IdentityID)
		assert.Equal(t, id, *e.IdentityID)
	})

	t.Run("case=two events have different IDs", func(t *testing.T) {
		s := &session.Session{ID: x.NewUUID(), IdentityID: x.NewUUID()}
		assert.NotEqual(t, NewSuccessEvent(r, newEventTestFlow(), s).EventID, NewSuccessEvent(r, newEventTestFlow(), s).EventID)
	})
}

func TestNewFailureEvent(t *testing.T) {
	r := httptest.NewRequest("POST", "/self-service/login", nil)
	r.RemoteAddr = "192.0.2.20:1234"

	t.Run("case=MFA failure", func(t *testing.T) {
		id := x.NewUUID()
		failure := NewMFAFailure(identity.CredentialsTypeLookup, ReasonDetailCodeAlreadyUsed, id, identity.AuthenticatorAssuranceLevel1)
		e := NewFailureEvent(r, newEventTestFlow(), &failure, "", "")

		assert.Equal(t, EventTypeVerified, e.Type)
		assert.Equal(t, EventDetailMFA, e.Detail)
		assert.Equal(t, EventResultDenied, e.Result)
		assert.Equal(t, ReasonInvalidCredentials, e.Reason)
		assert.Equal(t, ReasonDetailCodeAlreadyUsed, e.ReasonDetail)
		assert.Equal(t, identity.CredentialsTypeLookup, e.Method)
		assert.Equal(t, identity.AuthenticatorAssuranceLevel1, e.AAL)
		require.NotNil(t, e.IdentityID)
		assert.Equal(t, id, *e.IdentityID)
		assert.Nil(t, e.SessionID)
		// Without proxy headers httpx.ClientIP returns the remote address, as
		// stored for session devices.
		assert.Equal(t, "192.0.2.20:1234", e.ClientIP)
	})

	t.Run("case=first factor failure without identity", func(t *testing.T) {
		f := newEventTestFlow()
		f.Active = ""
		e := NewFailureEvent(r, f, &Failure{Result: EventResultFailure, Reason: ReasonLDAPUnavailable}, identity.CredentialsTypeLDAP, "bob")

		assert.Equal(t, EventTypeLogin, e.Type)
		assert.Empty(t, e.Detail)
		assert.Equal(t, EventResultFailure, e.Result)
		assert.Equal(t, ReasonLDAPUnavailable, e.Reason)
		assert.Equal(t, identity.CredentialsTypeLDAP, e.Method)
		assert.Nil(t, e.IdentityID)
		assert.Equal(t, "bob", e.ClaimedIdentifier)
	})
}

func TestEventPayloadContainsOnlyKnownFields(t *testing.T) {
	r := httptest.NewRequest("POST", "/self-service/login", nil)
	id := x.NewUUID()
	failure := NewMFAFailure(identity.CredentialsTypeTOTP, ReasonDetailInvalidCode, id, identity.AuthenticatorAssuranceLevel1)
	f := newEventTestFlow()
	f.RecordClaimedIdentifier(identity.CredentialsTypePassword, "alice")

	for name, e := range map[string]*Event{
		"success": NewSuccessEvent(r, f, &session.Session{ID: x.NewUUID(), IdentityID: id, Token: "ory_st_secret", LogoutToken: "ory_lo_secret"}),
		"failure": NewFailureEvent(r, f, &failure, identity.CredentialsTypePassword, "alice"),
	} {
		t.Run("event="+name, func(t *testing.T) {
			raw, err := json.Marshal(e)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "ory_st_secret")
			assert.NotContains(t, string(raw), "ory_lo_secret")

			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(raw, &fields))
			keys := make([]string, 0, len(fields))
			for k := range fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			allowed := map[string]bool{
				"event_id": true, "type": true, "detail": true, "occurred_at": true,
				"flow_id": true, "flow_type": true,
				"method": true, "requested_aal": true, "aal": true, "is_refresh": true,
				"result": true, "reason": true, "reason_detail": true,
				"identity_id": true, "claimed_identifier": true, "session_id": true,
				"client_ip": true, "user_agent": true,
			}
			for _, k := range keys {
				assert.True(t, allowed[k], "unexpected field %q in the login event: %s", k, raw)
			}
		})
	}
}
