// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package webauthn_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
)

func TestWebAuthnLoginEvents(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)
	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypePassword)+".enabled", false)
	enableWebAuthn(conf)

	router := x.NewRouterPublic()
	publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, router, x.NewRouterAdmin())
	errTS := testhelpers.NewErrorTestServer(t, reg)
	uiTS := testhelpers.NewLoginUIFlowEchoServer(t, reg)
	conf.MustSet(ctx, config.ViperKeySelfServiceErrorUI, errTS.URL+"/error-ts")
	conf.MustSet(ctx, config.ViperKeySelfServiceLoginUI, uiTS.URL+"/login-ts")
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/login.schema.json")
	conf.MustSet(ctx, config.ViperKeySecretsDefault, []string{"not-a-secure-session-key"})

	events := testhelpers.NewLoginEventReceiver(t, conf)

	// WebAuthn has no API flow, so only browser and SPA flows are covered.
	for _, k := range []struct {
		name string
		spa  bool
	}{{name: "browser"}, {name: "spa", spa: true}} {
		t.Run("flow="+k.name, func(t *testing.T) {
			t.Run("case=a rejected second factor sends a verified mfa event", func(t *testing.T) {
				id, identifier := createIdentityAndReturnIdentifier(t, reg, nil)
				hc := testhelpers.NewHTTPClientWithIdentitySessionCookie(t, reg, id)

				f := testhelpers.InitializeLoginFlowViaBrowser(t, hc, publicTS, false, k.spa, false, false,
					testhelpers.InitFlowWithAAL(identity.AuthenticatorAssuranceLevel2))
				values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
				values.Set("identifier", identifier)
				values.Set(node.WebAuthnLogin, string(loginFixtureSuccessResponseInvalid))
				body, _ := testhelpers.LoginMakeRequest(t, false, k.spa, f, hc, values.Encode())
				require.Equal(t, "The provided authentication code is invalid, please try again.",
					gjson.Get(body, "ui.messages.0.text").String(), "%s", body)

				e := events.Next(t)
				assert.Equal(t, login.EventTypeVerified, e.Type)
				assert.Equal(t, login.EventDetailMFA, e.Detail)
				assert.Equal(t, login.EventResultDenied, e.Result)
				assert.Equal(t, login.ReasonInvalidCredentials, e.Reason)
				assert.Equal(t, login.ReasonDetailInvalidAssertion, e.ReasonDetail)
				assert.Equal(t, identity.CredentialsTypeWebAuthn, e.Method)
				assert.Equal(t, identity.AuthenticatorAssuranceLevel2, e.RequestedAAL)
				assert.Equal(t, identity.AuthenticatorAssuranceLevel1, e.AAL)
				require.NotNil(t, e.IdentityID)
				assert.Equal(t, id.ID, *e.IdentityID)
				assert.Nil(t, e.SessionID)

				// The assertion never reaches the receiver.
				assert.False(t, gjson.GetBytes(e.Raw, node.WebAuthnLogin).Exists(), "%s", e.Raw)
				assert.NotContains(t, string(e.Raw), gjson.GetBytes(loginFixtureSuccessResponseInvalid, "response.signature").String())
				assert.NotContains(t, string(e.Raw), gjson.GetBytes(loginFixtureSuccessResponseInvalid, "response.clientDataJSON").String())
				events.AssertNone(t)
			})
		})
	}
}
