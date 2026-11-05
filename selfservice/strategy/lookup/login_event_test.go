// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package lookup_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/x"
)

func TestLookupLoginEvents(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)
	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypePassword)+".enabled", false)
	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeLookup)+".enabled", true)

	router := x.NewRouterPublic()
	publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, router, x.NewRouterAdmin())
	errTS := testhelpers.NewErrorTestServer(t, reg)
	uiTS := testhelpers.NewLoginUIFlowEchoServer(t, reg)
	redirTS := testhelpers.NewRedirSessionEchoTS(t, reg)
	conf.MustSet(ctx, config.ViperKeySelfServiceErrorUI, errTS.URL+"/error-ts")
	conf.MustSet(ctx, config.ViperKeySelfServiceLoginUI, uiTS.URL+"/login-ts")
	conf.MustSet(ctx, config.ViperKeySelfServiceBrowserDefaultReturnTo, redirTS.URL+"/return-ts")
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/login.schema.json")
	conf.MustSet(ctx, config.ViperKeySecretsDefault, []string{"not-a-secure-session-key"})

	events := testhelpers.NewLoginEventReceiver(t, conf)

	for _, k := range []struct {
		name     string
		api, spa bool
	}{{name: "api", api: true}, {name: "browser"}, {name: "spa", spa: true}} {
		submit := func(t *testing.T, id *identity.Identity, code string) (string, *http.Response) {
			var hc *http.Client
			if k.api {
				hc = testhelpers.NewHTTPClientWithIdentitySessionToken(t, reg, id)
			} else {
				hc = testhelpers.NewHTTPClientWithIdentitySessionCookie(t, reg, id)
			}
			aal2 := testhelpers.InitFlowWithAAL(identity.AuthenticatorAssuranceLevel2)
			f := testhelpers.InitializeLoginFlowViaAPI(t, hc, publicTS, false, aal2)
			if !k.api {
				f = testhelpers.InitializeLoginFlowViaBrowser(t, hc, publicTS, false, k.spa, false, false, aal2)
			}
			values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
			values.Set("method", identity.CredentialsTypeLookup.String())
			values.Set("lookup_secret", code)
			return testhelpers.LoginMakeRequest(t, k.api, k.spa, f, hc, testhelpers.EncodeFormAsJSON(t, k.api, values))
		}

		assertMFAFailure := func(t *testing.T, id *identity.Identity, reasonDetail, code string) {
			t.Helper()
			e := events.Next(t)
			assert.Equal(t, login.EventTypeVerified, e.Type)
			assert.Equal(t, login.EventDetailMFA, e.Detail)
			assert.Equal(t, login.EventResultDenied, e.Result)
			assert.Equal(t, login.ReasonInvalidCredentials, e.Reason)
			assert.Equal(t, reasonDetail, e.ReasonDetail)
			assert.Equal(t, identity.CredentialsTypeLookup, e.Method)
			assert.Equal(t, identity.AuthenticatorAssuranceLevel1, e.AAL)
			require.NotNil(t, e.IdentityID)
			assert.Equal(t, id.ID, *e.IdentityID)
			assert.False(t, gjson.GetBytes(e.Raw, "lookup_secret").Exists())
			assert.NotContains(t, string(e.Raw), code)
			events.AssertNone(t)
		}

		t.Run("flow="+k.name, func(t *testing.T) {
			// createIdentity gives every identity the codes key-0 to key-11,
			// of which key-1, key-4, key-7 and key-10 are used.
			t.Run("case=invalid code", func(t *testing.T) {
				id, _ := createIdentity(t, reg)
				submit(t, id, "not-a-lookup-code")
				assertMFAFailure(t, id, login.ReasonDetailInvalidCode, "not-a-lookup-code")
			})

			t.Run("case=code already used", func(t *testing.T) {
				id, _ := createIdentity(t, reg)
				submit(t, id, "key-1")
				assertMFAFailure(t, id, login.ReasonDetailCodeAlreadyUsed, "key-1")
			})

			t.Run("case=valid code", func(t *testing.T) {
				id, _ := createIdentity(t, reg)
				body, res := submit(t, id, "key-0")
				require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)

				e := events.Next(t)
				assert.Equal(t, login.EventTypeLogin, e.Type)
				assert.Equal(t, login.EventResultSuccess, e.Result)
				assert.Equal(t, identity.CredentialsTypeLookup, e.Method)
				assert.Equal(t, identity.AuthenticatorAssuranceLevel2, e.AAL)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, id.ID, *e.IdentityID)
				require.NotNil(t, e.SessionID)
				assert.NotContains(t, string(e.Raw), "key-0")
				events.AssertNone(t)
			})
		})
	}
}
