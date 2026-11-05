// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package totp_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	stdtotp "github.com/pquerna/otp/totp"
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

func TestTOTPLoginEvents(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)
	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypePassword), map[string]interface{}{"enabled": true})
	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeTOTP), map[string]interface{}{"enabled": true})

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
			values.Set("method", "totp")
			values.Set("totp_code", code)
			return testhelpers.LoginMakeRequest(t, k.api, k.spa, f, hc, testhelpers.EncodeFormAsJSON(t, k.api, values))
		}

		t.Run("flow="+k.name, func(t *testing.T) {
			t.Run("case=wrong code sends a verified mfa event", func(t *testing.T) {
				id, _, _ := createIdentity(t, reg)
				submit(t, id, "111111")

				e := events.Next(t)
				assert.Equal(t, login.EventTypeVerified, e.Type)
				assert.Equal(t, login.EventDetailMFA, e.Detail)
				assert.Equal(t, login.EventResultDenied, e.Result)
				assert.Equal(t, login.ReasonInvalidCredentials, e.Reason)
				assert.Equal(t, login.ReasonDetailInvalidCode, e.ReasonDetail)
				assert.Equal(t, identity.CredentialsTypeTOTP, e.Method)
				assert.Equal(t, identity.AuthenticatorAssuranceLevel2, e.RequestedAAL)
				assert.Equal(t, identity.AuthenticatorAssuranceLevel1, e.AAL)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, id.ID, *e.IdentityID)
				assert.Nil(t, e.SessionID)
				assert.False(t, gjson.GetBytes(e.Raw, "totp_code").Exists())
				events.AssertNone(t)
			})

			t.Run("case=correct code sends a login success event at aal2", func(t *testing.T) {
				id, _, key := createIdentity(t, reg)
				code, err := stdtotp.GenerateCode(key.Secret(), time.Now())
				require.NoError(t, err)
				body, res := submit(t, id, code)
				require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)

				e := events.Next(t)
				assert.Equal(t, login.EventTypeLogin, e.Type)
				assert.Equal(t, login.EventResultSuccess, e.Result)
				assert.Equal(t, identity.CredentialsTypeTOTP, e.Method)
				assert.Equal(t, identity.AuthenticatorAssuranceLevel2, e.RequestedAAL)
				assert.Equal(t, identity.AuthenticatorAssuranceLevel2, e.AAL)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, id.ID, *e.IdentityID)
				require.NotNil(t, e.SessionID)
				assert.False(t, gjson.GetBytes(e.Raw, "totp_code").Exists())
				events.AssertNone(t)
			})
		})
	}

}
