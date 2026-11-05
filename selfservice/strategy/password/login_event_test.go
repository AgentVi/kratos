// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package password_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/x"
	"github.com/ory/x/sqlxx"
)

func createPasswordIdentity(t *testing.T, reg *driver.RegistryDefault, identifier, password string, state identity.State) *identity.Identity {
	t.Helper()
	ctx := context.Background()
	p, err := reg.Hasher(ctx).Generate(ctx, []byte(password))
	require.NoError(t, err)
	i := &identity.Identity{
		ID:     x.NewUUID(),
		Traits: identity.Traits(fmt.Sprintf(`{"subject":"%s"}`, identifier)),
		State:  state,
		Credentials: map[identity.CredentialsType]identity.Credentials{
			identity.CredentialsTypePassword: {
				Type:        identity.CredentialsTypePassword,
				Identifiers: []string{identifier},
				Config:      sqlxx.JSONRawMessage(`{"hashed_password":"` + string(p) + `"}`),
			},
		},
	}
	require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, i))
	return i
}

// assertNoSecrets checks that none of the secrets of a login appear in the
// event that was sent for it.
func assertNoSecrets(t *testing.T, e testhelpers.ReceivedLoginEvent, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		assert.NotContains(t, string(e.Raw), secret)
	}
	for _, key := range []string{"password", "token", "session_token", "cookie", "cookies", "csrf_token", "totp_code", "lookup_secret", "webauthn_login"} {
		assert.False(t, gjson.GetBytes(e.Raw, key).Exists(), "%s must not be part of the event: %s", key, e.Raw)
	}
}

func TestLoginEvents(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)
	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypePassword), map[string]interface{}{"enabled": true})
	router := x.NewRouterPublic()
	publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, router, x.NewRouterAdmin())

	errTS := testhelpers.NewErrorTestServer(t, reg)
	uiTS := testhelpers.NewLoginUIFlowEchoServer(t, reg)
	redirTS := testhelpers.NewRedirSessionEchoTS(t, reg)
	conf.MustSet(ctx, config.ViperKeySelfServiceErrorUI, errTS.URL+"/error-ts")
	conf.MustSet(ctx, config.ViperKeySelfServiceLoginUI, uiTS.URL+"/login-ts")
	conf.MustSet(ctx, config.ViperKeySelfServiceBrowserDefaultReturnTo, redirTS.URL+"/return-ts")
	testhelpers.SetDefaultIdentitySchemaFromRaw(conf, loginSchema)
	conf.MustSet(ctx, config.ViperKeySecretsDefault, []string{"not-a-secure-session-key"})

	events := testhelpers.NewLoginEventReceiver(t, conf)

	const password = "a-very-secret-password-1234"

	type flowKind struct {
		name     string
		api, spa bool
		flowType string
	}
	kinds := []flowKind{
		{name: "api", api: true, flowType: "api"},
		{name: "browser", flowType: "browser"},
		{name: "spa", spa: true, flowType: "browser"},
	}

	newClient := func(t *testing.T, k flowKind) *http.Client {
		if k.api {
			return testhelpers.NewDebugClient(t)
		}
		return testhelpers.NewClientWithCookies(t)
	}

	initFlow := func(t *testing.T, k flowKind, hc *http.Client) (string, url.Values, func(url.Values) (string, *http.Response)) {
		var f = testhelpers.InitializeLoginFlowViaAPI(t, hc, publicTS, false)
		if !k.api {
			f = testhelpers.InitializeLoginFlowViaBrowser(t, hc, publicTS, false, k.spa, false, false)
		}
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "password")
		return f.Id, values, func(v url.Values) (string, *http.Response) {
			return testhelpers.LoginMakeRequest(t, k.api, k.spa, f, hc, testhelpers.EncodeFormAsJSON(t, k.api, v))
		}
	}

	for _, k := range kinds {
		k := k
		t.Run("flow="+k.name, func(t *testing.T) {
			t.Run("case=successful login sends a success event", func(t *testing.T) {
				identifier := "success-" + k.name + "@ory.sh"
				id := createPasswordIdentity(t, reg, identifier, password, identity.StateActive)

				hc := newClient(t, k)
				flowID, values, submit := initFlow(t, k, hc)
				values.Set("identifier", identifier)
				values.Set("password", password)
				body, res := submit(values)
				require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
				if !k.api && !k.spa {
					require.Contains(t, res.Request.URL.String(), "/return-ts", "%s", body)
				} else {
					require.NotEmpty(t, gjson.Get(body, "session.id").String(), "%s", body)
				}

				e := events.Next(t)
				assert.Equal(t, login.EventTypeLogin, e.Type)
				assert.Equal(t, login.EventResultSuccess, e.Result)
				assert.Empty(t, e.Reason)
				assert.Equal(t, identity.CredentialsTypePassword, e.Method)
				assert.Equal(t, identity.AuthenticatorAssuranceLevel1, e.RequestedAAL)
				assert.Equal(t, identity.AuthenticatorAssuranceLevel1, e.AAL)
				assert.False(t, e.IsRefresh)
				assert.Equal(t, flowID, e.FlowID.String())
				assert.Equal(t, k.flowType, e.FlowType)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, id.ID, *e.IdentityID)
				require.NotNil(t, e.SessionID)
				assert.NotEqual(t, uuid.Nil, *e.SessionID)
				assert.Equal(t, identifier, e.ClaimedIdentifier)
				assert.NotEmpty(t, e.ClientIP)
				assert.NotEmpty(t, e.UserAgent)
				assert.NotEqual(t, uuid.Nil, e.EventID)
				assert.Equal(t, e.EventID.String(), e.Headers.Get("Idempotency-Key"))
				assert.WithinDuration(t, time.Now(), e.OccurredAt, time.Minute)

				secrets := []string{password, gjson.Get(body, "session_token").String()}
				if u, err := url.Parse(publicTS.URL); err == nil && hc.Jar != nil {
					for _, c := range hc.Jar.Cookies(u) {
						secrets = append(secrets, c.Value)
					}
				}
				assertNoSecrets(t, e, secrets...)
				events.AssertNone(t)
			})

			t.Run("case=unknown identifier sends a denied event without identity", func(t *testing.T) {
				identifier := "unknown-" + k.name + "@ory.sh"
				hc := newClient(t, k)
				_, values, submit := initFlow(t, k, hc)
				values.Set("identifier", identifier)
				values.Set("password", password)
				submit(values)

				e := events.Next(t)
				assert.Equal(t, login.EventTypeLogin, e.Type)
				assert.Equal(t, login.EventResultDenied, e.Result)
				assert.Equal(t, login.ReasonInvalidCredentials, e.Reason)
				assert.Equal(t, login.ReasonDetailUnknownUser, e.ReasonDetail)
				assert.Equal(t, identity.CredentialsTypePassword, e.Method)
				assert.Nil(t, e.IdentityID)
				assert.True(t, gjson.GetBytes(e.Raw, "identity_id").Exists(), "identity_id must be sent as null: %s", e.Raw)
				assert.Nil(t, e.SessionID)
				assert.Equal(t, identifier, e.ClaimedIdentifier)
				assert.NotEmpty(t, e.ClientIP)
				assertNoSecrets(t, e, password)
				events.AssertNone(t)
			})

			t.Run("case=wrong password sends a denied event with identity", func(t *testing.T) {
				identifier := "wrong-password-" + k.name + "@ory.sh"
				id := createPasswordIdentity(t, reg, identifier, password, identity.StateActive)
				hc := newClient(t, k)
				_, values, submit := initFlow(t, k, hc)
				values.Set("identifier", identifier)
				values.Set("password", "not-the-password-5678")
				submit(values)

				e := events.Next(t)
				assert.Equal(t, login.EventResultDenied, e.Result)
				assert.Equal(t, login.ReasonInvalidCredentials, e.Reason)
				assert.Equal(t, login.ReasonDetailWrongPassword, e.ReasonDetail)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, id.ID, *e.IdentityID)
				assert.Equal(t, identifier, e.ClaimedIdentifier)
				assertNoSecrets(t, e, password, "not-the-password-5678")
				events.AssertNone(t)
			})

			t.Run("case=disabled identity sends a denied event", func(t *testing.T) {
				identifier := "disabled-" + k.name + "@ory.sh"
				id := createPasswordIdentity(t, reg, identifier, password, identity.StateInactive)
				hc := newClient(t, k)
				_, values, submit := initFlow(t, k, hc)
				values.Set("identifier", identifier)
				values.Set("password", password)
				submit(values)

				e := events.Next(t)
				assert.Equal(t, login.EventResultDenied, e.Result)
				assert.Equal(t, login.ReasonIdentityDisabled, e.Reason)
				assert.Equal(t, identity.CredentialsTypePassword, e.Method)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, id.ID, *e.IdentityID)
				assert.Equal(t, identifier, e.ClaimedIdentifier)
				assertNoSecrets(t, e, password)
				events.AssertNone(t)
			})

			t.Run("case=invalid payload sends nothing", func(t *testing.T) {
				hc := newClient(t, k)
				_, values, submit := initFlow(t, k, hc)
				values.Del("identifier")
				values.Set("password", password)
				submit(values)
				events.AssertNone(t)
			})

			t.Run("case=expired flow sends nothing", func(t *testing.T) {
				identifier := "expired-" + k.name + "@ory.sh"
				createPasswordIdentity(t, reg, identifier, password, identity.StateActive)
				hc := newClient(t, k)
				flowID, values, submit := initFlow(t, k, hc)
				f, err := reg.LoginFlowPersister().GetLoginFlow(ctx, uuid.FromStringOrNil(flowID))
				require.NoError(t, err)
				f.ExpiresAt = time.Now().Add(-time.Minute)
				require.NoError(t, reg.LoginFlowPersister().UpdateLoginFlow(ctx, f))

				values.Set("identifier", identifier)
				values.Set("password", "not-the-password-5678")
				submit(values)
				events.AssertNone(t)
			})

			if !k.api {
				t.Run("case=CSRF failure sends nothing", func(t *testing.T) {
					identifier := "csrf-" + k.name + "@ory.sh"
					createPasswordIdentity(t, reg, identifier, password, identity.StateActive)
					hc := newClient(t, k)
					_, values, submit := initFlow(t, k, hc)
					values.Set("identifier", identifier)
					values.Set("password", "not-the-password-5678")
					values.Set("csrf_token", "invalid-csrf-token")
					submit(values)
					events.AssertNone(t)
				})
			}
		})
	}

	t.Run("case=already logged in sends nothing", func(t *testing.T) {
		identifier := "already-logged-in@ory.sh"
		createPasswordIdentity(t, reg, identifier, password, identity.StateActive)
		k := kinds[2]
		hc := newClient(t, k)
		// Both flows are created before the first one logs in.
		_, firstValues, submitFirst := initFlow(t, k, hc)
		_, secondValues, submitSecond := initFlow(t, k, hc)

		firstValues.Set("identifier", identifier)
		firstValues.Set("password", password)
		submitFirst(firstValues)
		assert.Equal(t, login.EventResultSuccess, events.Next(t).Result)

		secondValues.Set("identifier", identifier)
		secondValues.Set("password", password)
		body, _ := submitSecond(secondValues)
		assert.Contains(t, body, "A valid session was detected")
		events.AssertNone(t)
	})

	t.Run("case=after login hook rejecting the login sends authorization_denied", func(t *testing.T) {
		hookTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"messages":[{"instance_ptr":"#/","messages":[{"id":4000001,"text":"not authorized","type":"error"}]}]}`))
		}))
		t.Cleanup(hookTS.Close)

		key := config.HookStrategyKey(config.ViperKeySelfServiceLoginAfter, identity.CredentialsTypePassword.String())
		conf.MustSet(ctx, key, []map[string]interface{}{{
			"hook": "web_hook",
			"config": map[string]interface{}{
				"url":      hookTS.URL,
				"method":   "POST",
				"body":     "base64://" + base64.StdEncoding.EncodeToString([]byte("function(ctx) {}")),
				"response": map[string]interface{}{"parse": true},
			},
		}})
		t.Cleanup(func() { conf.MustSet(ctx, key, nil) })

		for _, k := range kinds {
			t.Run("flow="+k.name, func(t *testing.T) {
				identifier := "rejected-" + k.name + "@ory.sh"
				id := createPasswordIdentity(t, reg, identifier, password, identity.StateActive)
				hc := newClient(t, k)
				_, values, submit := initFlow(t, k, hc)
				values.Set("identifier", identifier)
				values.Set("password", password)
				submit(values)

				e := events.Next(t)
				assert.Equal(t, login.EventTypeLogin, e.Type)
				assert.Equal(t, login.EventResultDenied, e.Result)
				assert.Equal(t, login.ReasonAuthorizationDenied, e.Reason)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, id.ID, *e.IdentityID)
				assert.Equal(t, identifier, e.ClaimedIdentifier)
				assertNoSecrets(t, e, password)
				events.AssertNone(t)
			})
		}
	})
}
