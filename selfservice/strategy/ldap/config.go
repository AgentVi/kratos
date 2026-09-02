package ldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"
	"github.com/ory/herodot"
	"github.com/ory/x/jsonx"
	"github.com/pkg/errors"
)

const (
	ldapScopeBaseObject   = "base_object"
	ldapScopeSingleLevel  = "single_level"
	ldapScopeWholeSubtree = "whole_subtree"
)

type IdentityAttribute struct {
	Name string `json:"name"`
	Attr string `json:"attr"`
}

type GroupUserMatcher struct {
	UserAttr  string `json:"user_attr"`
	GroupAttr string `json:"group_attr"`
}

type ldapSearchBase struct {
	DistinguishedName string `json:"base_dn"`
	SearchScope       string `json:"scope"`
}

type resolvedLDAPSearchBase struct {
	distinguishedName string
	searchScope       int
}

type Duration struct {
	time.Duration
}

type Configuration struct {
	SchemaId string `json:"schema_id"`
	// URL is the LDAP URL that begins with the ldap:// protocol prefix
	// or ldaps:// if the server is communicating over an TLS/SSL connection.
	URL string `json:"ldap_url"`

	// BindDN and BindPW are the service account credentials used while searching.
	BindDN string `json:"bind_dn"`
	BindPW string `json:"bind_pw"`

	// TLS configures how the connection to the directory server is encrypted.
	TLS ldapTLSConfiguration `json:"tls"`

	UserSearch struct {
		// BaseDN is the legacy single search base. BaseDNs provides multiple bases
		// with per-base scope; configuring both forms is invalid.
		BaseDN  string           `json:"base_dn"`
		BaseDNs []ldapSearchBase `json:"base_dns"`

		Filter string `json:"filter"`

		Username string `json:"username"`

		IdentityAttributes []IdentityAttribute `json:"identity_attributes"`
	} `json:"user_search"`

	GroupSearch struct {
		// BaseDN is the legacy single search base. BaseDNs provides multiple bases
		// with per-base scope; configuring both forms is invalid.
		BaseDN  string           `json:"base_dn"`
		BaseDNs []ldapSearchBase `json:"base_dns"`

		Filter string `json:"filter"`

		NameAttribute string `json:"name_attr"`

		// GroupsFromUserMemberOf resolves direct memberOf values only. Active
		// Directory nested and primary groups are intentionally not expanded.
		GroupsFromUserMemberOf bool `json:"groups_from_user_memberof"`

		UserMatchers []GroupUserMatcher `json:"user_matchers"`
	} `json:"group_search"`

	UpdateUserIdentity struct {
		Enabled bool `json:"enabled"`

		RefreshTime Duration `json:"refresh_time"`
	} `json:"update_user_identity"`

	// resolvedTLSMode and resolvedTLSConfig are derived from TLS by Config.
	// resolvedTLSConfig is nil when the connection is not TLS protected.
	resolvedTLSMode   string
	resolvedTLSConfig *tls.Config
}

func (s *Strategy) Config(ctx context.Context) (*Configuration, error) {
	var configuration Configuration

	rawConfiguration := s.d.Config().SelfServiceStrategy(ctx, string(s.ID())).Config
	if err := jsonx.NewStrictDecoder(bytes.NewBuffer(rawConfiguration)).Decode(&configuration); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to decode LDAP configuration: %s", err))
	}

	if err := configuration.validate(); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Invalid LDAP configuration: %s", err))
	}

	if err := configuration.resolveTLS(); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Invalid LDAP configuration: %s", err))
	}

	if configuration.TLS.InsecureSkipVerify {
		// Config runs on every login, so this is logged once per process.
		s.insecureTLSWarning.Do(func() {
			s.d.Logger().Warn("LDAP TLS certificate verification is disabled because selfservice.methods.ldap.config.tls.insecure_skip_verify is set. Do not use this outside of development.")
		})
	}

	return &configuration, nil
}

func (configuration *Configuration) validate() error {
	if err := configuration.TLS.validate(); err != nil {
		return errors.Wrap(err, "tls")
	}

	if _, err := resolveLDAPSearchBases(configuration.UserSearch.BaseDN, configuration.UserSearch.BaseDNs); err != nil {
		return errors.Wrap(err, "user_search")
	}
	if _, err := resolveLDAPSearchBases(configuration.GroupSearch.BaseDN, configuration.GroupSearch.BaseDNs); err != nil {
		return errors.Wrap(err, "group_search")
	}

	if configuration.UserSearch.Filter != "" {
		if _, err := ldapclient.CompileFilter(configuration.UserSearch.Filter); err != nil {
			return errors.Wrap(err, "invalid user_search.filter")
		}
	}
	if configuration.GroupSearch.Filter != "" {
		if _, err := ldapclient.CompileFilter(configuration.GroupSearch.Filter); err != nil {
			return errors.Wrap(err, "invalid group_search.filter")
		}
	}

	if !configuration.GroupSearch.GroupsFromUserMemberOf && len(configuration.GroupSearch.UserMatchers) == 0 {
		return errors.New("group_search.user_matchers must contain at least one matcher when groups_from_user_memberof is false")
	}

	return nil
}

// resolveTLS derives the effective TLS mode and configuration. The certificates
// are loaded here rather than at dial time so that unreadable files or malformed
// PEM content surface as a configuration error instead of a runtime failure.
func (configuration *Configuration) resolveTLS() error {
	mode, err := resolveLDAPTLSMode(configuration.TLS.Mode, configuration.URL)
	if err != nil {
		return errors.Wrap(err, "tls")
	}

	tlsConfiguration, err := buildLDAPTLSConfig(configuration, mode)
	if err != nil {
		return errors.Wrap(err, "tls")
	}

	configuration.resolvedTLSMode = mode
	configuration.resolvedTLSConfig = tlsConfiguration

	return nil
}

func resolveLDAPSearchBases(legacyBaseDN string, configuredBases []ldapSearchBase) ([]resolvedLDAPSearchBase, error) {
	if legacyBaseDN != "" && len(configuredBases) > 0 {
		return nil, errors.New("base_dn and base_dns cannot be configured together")
	}

	if len(configuredBases) == 0 {
		return []resolvedLDAPSearchBase{{
			distinguishedName: legacyBaseDN,
			searchScope:       ldapclient.ScopeWholeSubtree,
		}}, nil
	}

	resolvedBases := make([]resolvedLDAPSearchBase, 0, len(configuredBases))
	for index, configuredBase := range configuredBases {
		if configuredBase.DistinguishedName == "" {
			return nil, errors.Errorf("base_dns[%d].base_dn must not be empty", index)
		}

		searchScope, err := resolveLDAPSearchScope(configuredBase.SearchScope)
		if err != nil {
			return nil, errors.Wrapf(err, "base_dns[%d]", index)
		}

		resolvedBases = append(resolvedBases, resolvedLDAPSearchBase{
			distinguishedName: configuredBase.DistinguishedName,
			searchScope:       searchScope,
		})
	}

	return resolvedBases, nil
}

func resolveLDAPSearchScope(configuredScope string) (int, error) {
	switch configuredScope {
	case "", ldapScopeWholeSubtree:
		return ldapclient.ScopeWholeSubtree, nil
	case ldapScopeBaseObject:
		return ldapclient.ScopeBaseObject, nil
	case ldapScopeSingleLevel:
		return ldapclient.ScopeSingleLevel, nil
	default:
		return 0, errors.Errorf("unsupported scope %q", configuredScope)
	}
}

func (duration *Duration) UnmarshalJSON(b []byte) error {
	var unmarshalledJSON interface{}

	err := json.Unmarshal(b, &unmarshalledJSON)
	if err != nil {
		return err
	}

	switch value := unmarshalledJSON.(type) {
	case string:
		duration.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid duration: %#v", unmarshalledJSON)
	}

	return nil
}
