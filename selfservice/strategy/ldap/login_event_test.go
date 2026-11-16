// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"crypto/tls"
	"crypto/x509"
	stderrors "errors"
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/selfservice/flow/login"
)

func TestLDAPLoginFailure_EveryLDAPLoginError_ShouldBeClassifiedForTheLoginEvent(t *testing.T) {
	user := newLDAPTestUser()
	otherUser := newLDAPTestUser()
	otherUser.DN = "CN=Other Alice,OU=Users,DC=example,DC=com"
	findUser := func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
		return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&user}}, nil
	}

	for _, tc := range []struct {
		name         string
		configure    func(*Configuration)
		connections  func() []*ldapConnectionMock
		dialErr      error
		result       login.EventResult
		reason       string
		reasonDetail string
	}{
		{
			name: "unknown user",
			connections: func() []*ldapConnectionMock {
				return []*ldapConnectionMock{{}}
			},
			result:       login.EventResultDenied,
			reason:       login.ReasonInvalidCredentials,
			reasonDetail: login.ReasonDetailUnknownUser,
		},
		{
			name: "several users match",
			connections: func() []*ldapConnectionMock {
				return []*ldapConnectionMock{{searchFunc: func(*ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
					return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&user, &otherUser}}, nil
				}}}
			},
			result:       login.EventResultDenied,
			reason:       login.ReasonInvalidCredentials,
			reasonDetail: login.ReasonDetailAmbiguousUser,
		},
		{
			name: "several users match across search bases",
			configure: func(c *Configuration) {
				c.UserSearch.BaseDN = ""
				c.UserSearch.BaseDNs = []ldapSearchBase{
					{DistinguishedName: "OU=Employees,DC=example,DC=com"},
					{DistinguishedName: "OU=Contractors,DC=example,DC=com"},
				}
			},
			connections: func() []*ldapConnectionMock {
				searches := 0
				return []*ldapConnectionMock{{searchFunc: func(*ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
					searches++
					if searches == 1 {
						return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&user}}, nil
					}
					return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&otherUser}}, nil
				}}}
			},
			result:       login.EventResultDenied,
			reason:       login.ReasonInvalidCredentials,
			reasonDetail: login.ReasonDetailAmbiguousUser,
		},
		{
			name: "wrong password",
			connections: func() []*ldapConnectionMock {
				return []*ldapConnectionMock{
					{searchFunc: findUser},
					{bindFunc: func(string, string) error {
						return ldapclient.NewError(ldapclient.LDAPResultInvalidCredentials, stderrors.New("invalid password"))
					}},
				}
			},
			result:       login.EventResultDenied,
			reason:       login.ReasonInvalidCredentials,
			reasonDetail: login.ReasonDetailWrongPassword,
		},
		{
			name: "service account bind fails",
			connections: func() []*ldapConnectionMock {
				return []*ldapConnectionMock{{bindFunc: func(string, string) error {
					return ldapclient.NewError(ldapclient.LDAPResultInvalidCredentials, stderrors.New("service account rejected"))
				}}}
			},
			result: login.EventResultFailure,
			reason: login.ReasonLDAPUnavailable,
		},
		{
			name: "user search fails",
			connections: func() []*ldapConnectionMock {
				return []*ldapConnectionMock{{searchFunc: func(*ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
					return nil, ldapclient.NewError(ldapclient.LDAPResultBusy, stderrors.New("busy"))
				}}}
			},
			result: login.EventResultFailure,
			reason: login.ReasonLDAPUnavailable,
		},
		{
			name: "group search fails",
			connections: func() []*ldapConnectionMock {
				searches := 0
				return []*ldapConnectionMock{
					{searchFunc: func(r *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
						searches++
						if searches == 1 {
							return findUser(r)
						}
						return nil, stderrors.New("directory unavailable")
					}},
					{},
				}
			},
			result: login.EventResultFailure,
			reason: login.ReasonLDAPUnavailable,
		},
		{
			name:      "StartTLS fails",
			configure: func(c *Configuration) { c.TLS.Mode = ldapTLSModeStartTLS },
			connections: func() []*ldapConnectionMock {
				return []*ldapConnectionMock{{startTLSFunc: func(*tls.Config) error {
					return stderrors.New("server does not support StartTLS")
				}}}
			},
			result: login.EventResultFailure,
			reason: login.ReasonLDAPUnavailable,
		},
		{
			name: "LDAPS handshake fails",
			configure: func(c *Configuration) {
				c.URL = "ldaps://directory.example.test"
			},
			dialErr: x509.UnknownAuthorityError{},
			result:  login.EventResultFailure,
			reason:  login.ReasonLDAPUnavailable,
		},
		{
			name:    "directory unreachable",
			dialErr: stderrors.New("dial tcp: connection refused"),
			result:  login.EventResultFailure,
			reason:  login.ReasonLDAPUnavailable,
		},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			// Arrange
			ldapConfig := newLDAPTestConfiguration()
			if tc.configure != nil {
				tc.configure(ldapConfig)
			}
			var connections []*ldapConnectionMock
			if tc.connections != nil {
				connections = tc.connections()
			}
			ctx, strategy := newLDAPTestStrategy(t, ldapConfig, connections...)
			if tc.dialErr != nil {
				strategy.ldapDial = func(string, ...ldapclient.DialOpt) (ldapConnection, error) {
					return nil, tc.dialErr
				}
			}

			// Act
			_, _, err := strategy.ldapLogin(ctx, "alice", "password")
			require.Error(t, err)
			failure, ok := ldapLoginFailure(err)

			// Assert
			require.True(t, ok, "%+v", err)
			assert.Equal(t, tc.result, failure.Result)
			assert.Equal(t, tc.reason, failure.Reason)
			assert.Equal(t, tc.reasonDetail, failure.ReasonDetail)
		})
	}
}

func TestLDAPLoginFailure_ConfigurationFailure_ShouldNotProduceAnEvent(t *testing.T) {
	// Act
	_, ok := ldapLoginFailure(stderrors.New("LDAP configuration is invalid"))

	// Assert
	assert.False(t, ok)
}
