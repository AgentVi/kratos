package ldap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ory/herodot"
	"github.com/ory/x/jsonx"
	"github.com/pkg/errors"
)

type IdentityAttribute struct {
	Name string `json:"name"`
	Attr string `json:"attr"`
}

type GroupUserMatcher struct {
	UserAttr  string `json:"user_attr"`
	GroupAttr string `json:"group_attr"`
}

type Duration struct {
	time.Duration
}

type Configuration struct {
	// URL is the LDAP URL that begins with the ldap:// protocol prefix
	// or ldaps:// if the server is communicating over an TLS/SSL connection
	URL string `json:"ldap_url"`

	// BindDN and BindPW are the credentials of the service account that used
	// in the phase of users and groups searching
	BindDN string `json:"bind_dn"`
	BindPW string `json:"bind_pw"`

	// UserSearch configuration
	UserSearch struct {
		// BaseDN to start searching, eg. "ou=people,dc=example,dc=com"
		BaseDN string `json:"base_dn"`

		// Filter applied on searching (Optional), eg. "(objectClass=person)"
		Filter string `json:"filter"`

		// Username attribute for comparing user entries
		Username string `json:"username"`

		// Extracting identity attributes
		IdentityAttributes []IdentityAttribute `json:"identity_attributes"`
	} `json:"user_search"`

	// GroupSearch configuration
	GroupSearch struct {
		// BaseDN to start searching, eg. "ou=groups,dc=example,dc=com"
		BaseDN string `json:"base_dn"`

		// Filter applied on searching (Optional), eg. "(objectClass=groupOfUniqueNames)"
		Filter string `json:"filter"`

		// Represents group name, eg. cn
		NameAttribute string `json:"name_attr"`

		// Get groups list from user's memberOf attribute
		GroupsFromUserMemberOf bool `json:"groups_from_user_memberof"`

		// Additional group and user attributes matcher, will be ignored when GroupsFromUserMemberOf is true
		UserMatchers []GroupUserMatcher `json:"user_matchers"`
	} `json:"group_search"`

	// Update user identity when the user is authenticated
	UpdateUserIdentity struct {
		// Enable updating the user identity
		Enabled bool `json:"enabled"`

		// The user identity should be refreshed once the user is authenticated and outdated,
		// oudated = last update time + refresh time
		RefreshTime Duration `json:"refresh_time"`
	} `json:"update_user_identity"`
}

func (s *Strategy) Config(ctx context.Context) (*Configuration, error) {
	var c Configuration

	conf := s.d.Config().SelfServiceStrategy(ctx, string(s.ID())).Config
	if err := jsonx.
		NewStrictDecoder(bytes.NewBuffer(conf)).
		Decode(&c); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to decode LDAP configuration: %s", err))
	}

	return &c, nil
}

func (duration *Duration) UnmarshalJSON(b []byte) error {
	var unmarshalledJson interface{}

	err := json.Unmarshal(b, &unmarshalledJson)
	if err != nil {
		return err
	}

	switch value := unmarshalledJson.(type) {
	case string:
		duration.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid duration: %#v", unmarshalledJson)
	}

	return nil
}
