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
	"github.com/ory/kratos/selfservice/strategy/ldap"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

const (
	firstLoginServiceDN  = "cn=admin,dc=example,dc=org"
	firstLoginServicePW  = "service-password"
	firstLoginUserBaseDN = "ou=users,dc=example,dc=org"
)

// newIdentityCreatingAfterLoginHook acts like the IRIS+ after login web hook:
// on the first login it creates the identity and answers with its ID only.
func newIdentityCreatingAfterLoginHook(t *testing.T, reg *driver.RegistryDefault) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		loginID := gjson.GetBytes(body, "identity.traits.loginId").String()

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
			require.NoError(t, reg.IdentityManager().Create(ctx, i))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"identity": map[string]interface{}{"id": i.ID}})
	}))
	t.Cleanup(ts.Close)
	return ts
}

// TestLDAPFirstLogin checks that a login in which the after login web hook
// creates the identity continues with the saved identity. Before the fix, the
// session kept the in-memory identity of the LDAP strategy, which has no NID:
// with session.whoami.required_aal set to highest_available, a browser or SPA
// login then failed with "Received empty nid." after the session cookie was
// issued, and an API login returned the session without its identity.
func TestLDAPFirstLogin(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)

	testhelpers.SetIdentitySchemas(t, conf, map[string]string{
		"default": "file://../../../contrib/quickstart/kratos/ldap/identity.schema.json",
		"ldap":    "file://../../../contrib/quickstart/kratos/ldap/identity.schema.json",
	})
	conf.MustSet(ctx, config.ViperKeyDefaultIdentitySchemaID, "default")
	conf.MustSet(ctx, config.ViperKeySessionWhoAmIAAL, config.HighestAvailableAAL)
	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+".ldap", map[string]interface{}{
		"enabled": true,
		"config": map[string]interface{}{
			"ldap_url": "ldap://directory.example.test",
			"bind_dn":  firstLoginServiceDN,
			"bind_pw":  firstLoginServicePW,
			"user_search": map[string]interface{}{
				"base_dn":  firstLoginUserBaseDN,
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
		ServiceDN:         firstLoginServiceDN,
		ServicePassword:   firstLoginServicePW,
		UserBaseDN:        firstLoginUserBaseDN,
		UsernameAttribute: "uid",
	}
	strategy, err := reg.AllLoginStrategies().Strategy(identity.CredentialsTypeLDAP)
	require.NoError(t, err)
	ldap.UseFakeDirectory(strategy.(*ldap.Strategy), directory)

	hookTS := newIdentityCreatingAfterLoginHook(t, reg)
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

	savedIdentityID := func(t *testing.T, username string) uuid.UUID {
		i, _, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeLDAP, username)
		require.NoError(t, err)
		return i.ID
	}

	for _, k := range []struct {
		name     string
		api, spa bool
	}{{name: "api", api: true}, {name: "browser"}, {name: "spa", spa: true}} {
		t.Run("flow="+k.name, func(t *testing.T) {
			username := "first-login-" + k.name
			password := "secret-" + k.name
			directory.SetUser(username, ldap.FakeDirectoryUser{DN: fmt.Sprintf("uid=%s,%s", username, firstLoginUserBaseDN), Password: password})

			login := func(t *testing.T) (string, *http.Response) {
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

			assertLoggedInAsSavedIdentity := func(t *testing.T, body string, res *http.Response) {
				t.Helper()
				require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
				id := savedIdentityID(t, username)

				if !k.api && !k.spa {
					// The redirect echo server returns the session.
					require.Contains(t, res.Request.URL.String(), redirTS.URL+"/return-ts", "%s", body)
					assert.Equal(t, id.String(), gjson.Get(body, "identity.id").String(), "%s", body)
					return
				}

				require.NotEmpty(t, gjson.Get(body, "session.id").String(), "%s", body)
				assert.Equal(t, id.String(), gjson.Get(body, "session.identity.id").String(), "%s", body)
				assert.Equal(t, username, gjson.Get(body, "session.identity.traits.loginId").String(), "%s", body)

				sess, err := reg.SessionPersister().GetSession(ctx, uuid.FromStringOrNil(gjson.Get(body, "session.id").String()), session.ExpandNothing)
				require.NoError(t, err)
				assert.Equal(t, id, sess.IdentityID)
			}

			t.Run("case=first login", func(t *testing.T) {
				body, res := login(t)
				assertLoggedInAsSavedIdentity(t, body, res)
			})

			t.Run("case=returning login", func(t *testing.T) {
				body, res := login(t)
				assertLoggedInAsSavedIdentity(t, body, res)
			})
		})
	}
}
