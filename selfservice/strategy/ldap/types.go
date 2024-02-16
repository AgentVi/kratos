package ldap

import (
	"bytes"
	"encoding/json"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/x"
	"github.com/pkg/errors"
)

// submitSelfServiceLoginFlowWithLDAPMethodBody is used to decode the login form payload.
//
// swagger:model submitSelfServiceLoginFlowWithLDAPMethodBody
type submitSelfServiceLoginFlowWithLDAPMethodBody struct {
	// Method should be set to "ldap" when logging in using the identifier and password strategy.
	//
	// required: true
	Method string `json:"method"`

	// Sending the anti-csrf token is only required for browser login flows.
	CSRFToken string `json:"csrf_token"`

	// The user's password.
	//
	// required: true
	Password string `json:"ldap_password"`

	// Identifier is the email or username of the user trying to log in.
	//
	// required: true
	Identifier string `json:"ldap_identifier"`
}

type CredentialsConfig struct {
	DN string `json:"dn"`
}

func NewCredentials(dn string) (*identity.Credentials, error) {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(CredentialsConfig{DN: dn}); err != nil {
		return nil, errors.WithStack(x.PseudoPanic.WithDebugf("Unable to encode LDAP credential options to JSON: %s", err))
	}

	return &identity.Credentials{
		Type:        identity.CredentialsTypeLDAP,
		Identifiers: []string{dn},
		Config:      b.Bytes(),
	}, nil
}

// FlowMethod contains the configuration for this selfservice strategy.
type FlowMethod struct {
	*container.Container
}
