// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package ldap_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
	"github.com/ory/kratos/selfservice/strategy/ldap"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

const (
	testServiceDN  = "cn=admin,dc=example,dc=org"
	testServicePW  = "service-password"
	testUserBaseDN = "ou=users,dc=example,dc=org"
)

// newIRISAfterLoginHook acts like the IRIS+ after login web hook for LDAP: it
// creates the identity on the first login and rejects "mallory".
func newIRISAfterLoginHook(t *testing.T, reg *driver.RegistryDefault) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		loginID := gjson.GetBytes(body, "identity.traits.loginId").String()

		if loginID == "mallory" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"messages":[{"instance_ptr":"#/","messages":[{"id":4000001,"text":"not authorized","type":"error"}]}]}`))
			return
		}

		ctx := context.Background()
		i, _, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeLDAP, loginID)
		if err != nil {
			i = &identity.Identity{
				ID:       x.NewUUID(),
				SchemaID: "ldap",
				Traits:   identity.Traits(gjson.GetBytes(body, "identity.traits").Raw),
				Credentials: map[identity.CredentialsType]identity.Credentials{
					identity.CredentialsTypeLDAP: {
						Type:        identity.CredentialsTypeLDAP,
						Identifiers: []string{loginID},
						Config:      []byte(`{}`),
					},
				},
			}
			require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, i))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"identity": map[string]interface{}{"id": i.ID}})
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestLDAPLoginEvents(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)

	testhelpers.SetIdentitySchemas(t, conf, map[string]string{
		"default": "file://../../../contrib/quickstart/kratos/ldap/identity.schema.json",
		"ldap":    "file://../../../contrib/quickstart/kratos/ldap/identity.schema.json",
	})
	conf.MustSet(ctx, config.ViperKeyDefaultIdentitySchemaID, "default")
	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+".ldap", map[string]interface{}{
		"enabled": true,
		"config": map[string]interface{}{
			"ldap_url": "ldap://directory.example.test",
			"bind_dn":  testServiceDN,
			"bind_pw":  testServicePW,
			"user_search": map[string]interface{}{
				"base_dn":  testUserBaseDN,
				"filter":   "(objectClass=inetOrgPerson)",
				"username": "uid",
			},
			"group_search": map[string]interface{}{
				"base_dn":       "ou=groups,dc=example,dc=org",
				"filter":        "(objectClass=groupOfUniqueNames)",
				"name_attr":     "cn",
				"user_matchers": []map[string]interface{}{{"user_attr": "uid", "group_attr": "uniqueMember"}},
			},
		},
	})

	directory := &ldap.FakeDirectory{
		ServiceDN:         testServiceDN,
		ServicePassword:   testServicePW,
		UserBaseDN:        testUserBaseDN,
		UsernameAttribute: "uid",
	}
	strategy, err := reg.AllLoginStrategies().Strategy(identity.CredentialsTypeLDAP)
	require.NoError(t, err)
	ldap.UseFakeDirectory(strategy.(*ldap.Strategy), directory)

	hookTS := newIRISAfterLoginHook(t, reg)
	conf.MustSet(ctx, config.HookStrategyKey(config.ViperKeySelfServiceLoginAfter, identity.CredentialsTypeLDAP.String()), []map[string]interface{}{{
		"hook": "web_hook",
		"config": map[string]interface{}{
			"url":      hookTS.URL,
			"method":   "POST",
			"body":     "base64://" + base64.StdEncoding.EncodeToString([]byte("function(ctx) { identity: ctx.identity }")),
			"response": map[string]interface{}{"parse": true},
		},
	}})

	router := x.NewRouterPublic()
	publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, router, x.NewRouterAdmin())
	errTS := testhelpers.NewErrorTestServer(t, reg)
	uiTS := testhelpers.NewLoginUIFlowEchoServer(t, reg)
	redirTS := testhelpers.NewRedirSessionEchoTS(t, reg)
	conf.MustSet(ctx, config.ViperKeySelfServiceErrorUI, errTS.URL+"/error-ts")
	conf.MustSet(ctx, config.ViperKeySelfServiceLoginUI, uiTS.URL+"/login-ts")
	conf.MustSet(ctx, config.ViperKeySelfServiceBrowserDefaultReturnTo, redirTS.URL+"/return-ts")
	conf.MustSet(ctx, config.ViperKeySecretsDefault, []string{"not-a-secure-session-key"})
	// With highest_available, the first LDAP login of a browser flow fails
	// after the session was saved: the AAL check stores the available AAL on
	// the in-memory identity the after login hook filled in, which has no NID
	// ("Received empty nid."). That is unrelated to the login events.
	conf.MustSet(ctx, config.ViperKeySessionWhoAmIAAL, "aal1")

	events := testhelpers.NewLoginEventReceiver(t, conf)

	type flowKind struct {
		name     string
		api, spa bool
	}
	kinds := []flowKind{{name: "api", api: true}, {name: "browser"}, {name: "spa", spa: true}}

	submit := func(t *testing.T, k flowKind, username, password string) (string, *http.Response) {
		var hc *http.Client
		if k.api {
			hc = testhelpers.NewDebugClient(t)
		} else {
			hc = testhelpers.NewClientWithCookies(t)
		}
		f := testhelpers.InitializeLoginFlowViaAPI(t, hc, publicTS, false)
		if !k.api {
			f = testhelpers.InitializeLoginFlowViaBrowser(t, hc, publicTS, false, k.spa, false, false)
		}
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "ldap")
		values.Set("ldap_identifier", username)
		values.Set("ldap_password", password)
		return testhelpers.LoginMakeRequest(t, k.api, k.spa, f, hc, testhelpers.EncodeFormAsJSON(t, k.api, values))
	}

	identityIDOf := func(t *testing.T, username string) uuid.UUID {
		i, _, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeLDAP, username)
		require.NoError(t, err)
		return i.ID
	}

	for _, k := range kinds {
		t.Run("flow="+k.name, func(t *testing.T) {
			username := "alice-" + k.name
			password := "alice-secret-" + k.name
			directory.SetUser(username, ldap.FakeDirectoryUser{DN: fmt.Sprintf("uid=%s,%s", username, testUserBaseDN), Password: password})

			t.Run("case=first login carries the identity the after login hook created", func(t *testing.T) {
				body, res := submit(t, k, username, password)
				require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
				if !k.api && !k.spa {
					require.Contains(t, res.Request.URL.String(), "/return-ts", "%s", body)
				} else {
					require.NotEmpty(t, gjson.Get(body, "session.id").String(), "%s", body)
				}

				e := events.Next(t)
				assert.Equal(t, login.EventTypeLogin, e.Type)
				assert.Equal(t, login.EventResultSuccess, e.Result)
				assert.Equal(t, identity.CredentialsTypeLDAP, e.Method)
				assert.Equal(t, identity.AuthenticatorAssuranceLevel1, e.AAL)
				assert.Equal(t, username, e.ClaimedIdentifier)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, identityIDOf(t, username), *e.IdentityID, "the event must carry the saved identity, not the temporary one")
				require.NotNil(t, e.SessionID)
				sess, err := reg.SessionPersister().GetSession(ctx, *e.SessionID, session.ExpandNothing)
				require.NoError(t, err)
				assert.Equal(t, *e.IdentityID, sess.IdentityID)
				assert.NotContains(t, string(e.Raw), password)
				events.AssertNone(t)
			})

			t.Run("case=returning login", func(t *testing.T) {
				body, res := submit(t, k, username, password)
				require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
				if !k.api && !k.spa {
					require.Contains(t, res.Request.URL.String(), "/return-ts", "%s", body)
				} else {
					require.NotEmpty(t, gjson.Get(body, "session.id").String(), "%s", body)
				}

				e := events.Next(t)
				assert.Equal(t, login.EventResultSuccess, e.Result)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, identityIDOf(t, username), *e.IdentityID)
				events.AssertNone(t)
			})

			t.Run("case=wrong password", func(t *testing.T) {
				submit(t, k, username, "not-the-password")

				e := events.Next(t)
				assert.Equal(t, login.EventResultDenied, e.Result)
				assert.Equal(t, login.ReasonInvalidCredentials, e.Reason)
				assert.Equal(t, login.ReasonDetailWrongPassword, e.ReasonDetail)
				assert.Equal(t, identity.CredentialsTypeLDAP, e.Method)
				assert.Equal(t, username, e.ClaimedIdentifier)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, identityIDOf(t, username), *e.IdentityID)
				assert.NotContains(t, string(e.Raw), "not-the-password")
				events.AssertNone(t)
			})
		})
	}

	t.Run("case=unknown user", func(t *testing.T) {
		submit(t, kinds[1], "nobody", "whatever")

		e := events.Next(t)
		assert.Equal(t, login.EventResultDenied, e.Result)
		assert.Equal(t, login.ReasonInvalidCredentials, e.Reason)
		assert.Equal(t, login.ReasonDetailUnknownUser, e.ReasonDetail)
		assert.Equal(t, "nobody", e.ClaimedIdentifier)
		assert.Nil(t, e.IdentityID)
		events.AssertNone(t)
	})

	t.Run("case=directory unavailable", func(t *testing.T) {
		directory.SetUnavailable(true)
		t.Cleanup(func() { directory.SetUnavailable(false) })

		submit(t, kinds[1], "alice-browser", "alice-secret-browser")

		e := events.Next(t)
		assert.Equal(t, login.EventResultFailure, e.Result)
		assert.Equal(t, login.ReasonLDAPUnavailable, e.Reason)
		assert.Equal(t, "alice-browser", e.ClaimedIdentifier)
		require.NotNil(t, e.IdentityID, "the identity is known from an earlier login")
		assert.Equal(t, identityIDOf(t, "alice-browser"), *e.IdentityID)
		assert.NotContains(t, string(e.Raw), "alice-secret-browser")
		events.AssertNone(t)
	})

	t.Run("case=after login hook rejects the user", func(t *testing.T) {
		directory.SetUser("mallory", ldap.FakeDirectoryUser{DN: "uid=mallory," + testUserBaseDN, Password: "mallory-secret"})
		for _, k := range kinds {
			t.Run("flow="+k.name, func(t *testing.T) {
				submit(t, k, "mallory", "mallory-secret")

				e := events.Next(t)
				assert.Equal(t, login.EventTypeLogin, e.Type)
				assert.Equal(t, login.EventResultDenied, e.Result)
				assert.Equal(t, login.ReasonAuthorizationDenied, e.Reason)
				assert.Equal(t, identity.CredentialsTypeLDAP, e.Method)
				assert.Equal(t, "mallory", e.ClaimedIdentifier)
				assert.Nil(t, e.IdentityID, "IRIS+ never created the identity")
				assert.NotContains(t, string(e.Raw), "mallory-secret")
				events.AssertNone(t)
			})
		}
	})

}
