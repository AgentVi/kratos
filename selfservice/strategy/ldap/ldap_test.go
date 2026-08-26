package ldap

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/schema"
	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"
	pkgerrors "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ldapConnectionMock struct {
	bindFunc   func(username string, password string) error
	closeFunc  func() error
	searchFunc func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error)
}

type ldapTestDependencies struct {
	dependencies
	configuration *config.Config
	logger        *logrusx.Logger
}

func (m *ldapTestDependencies) Config() *config.Config {
	return m.configuration
}

func (m *ldapTestDependencies) Logger() *logrusx.Logger {
	return m.logger
}

func (m *ldapConnectionMock) Bind(username string, password string) error {
	if m.bindFunc == nil {
		return nil
	}

	return m.bindFunc(username, password)
}

func (m *ldapConnectionMock) Close() error {
	if m.closeFunc == nil {
		return nil
	}

	return m.closeFunc()
}

func (m *ldapConnectionMock) Search(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
	if m.searchFunc == nil {
		return &ldapclient.SearchResult{}, nil
	}

	return m.searchFunc(searchRequest)
}

func newLDAPTestConfiguration() *Configuration {
	conf := &Configuration{
		URL:    "ldap://directory.example.test",
		BindDN: "CN=service,DC=example,DC=com",
		BindPW: "service-password",
	}
	conf.UserSearch.BaseDN = "OU=Users,DC=example,DC=com"
	conf.UserSearch.Filter = "(objectClass=user)"
	conf.UserSearch.Username = "sAMAccountName"
	conf.UserSearch.IdentityAttributes = []IdentityAttribute{{Name: "firstName", Attr: "givenName"}}
	conf.GroupSearch.BaseDN = "OU=Groups,DC=example,DC=com"
	conf.GroupSearch.Filter = "(objectClass=group)"
	conf.GroupSearch.UserMatchers = []GroupUserMatcher{{UserAttr: "employeeID", GroupAttr: "member"}}

	return conf
}

func newLDAPTestStrategy(t *testing.T, ldapConfig *Configuration, connections ...*ldapConnectionMock) (context.Context, *Strategy) {
	t.Helper()

	ctx := context.Background()
	logger := logrusx.New("LDAP test", "")
	runtimeConfig, err := config.New(ctx, logger, io.Discard, configx.SkipValidation())
	require.NoError(t, err)

	strategyConfig, err := json.Marshal(ldapConfig)
	require.NoError(t, err)

	var strategyConfigMap map[string]interface{}
	require.NoError(t, json.Unmarshal(strategyConfig, &strategyConfigMap))
	delete(strategyConfigMap, "update_user_identity")
	runtimeConfig.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+".ldap", map[string]interface{}{
		"enabled": true,
		"config":  strategyConfigMap,
	})

	strategy := &Strategy{d: &ldapTestDependencies{configuration: runtimeConfig, logger: logger}}
	connectionIndex := 0
	strategy.ldapDial = func(url string, options ...ldapclient.DialOpt) (ldapConnection, error) {
		if !assert.Less(t, connectionIndex, len(connections), "unexpected LDAP connection") {
			return nil, stderrors.New("unexpected LDAP connection")
		}

		assert.Equal(t, ldapConfig.URL, url)
		connection := connections[connectionIndex]
		connectionIndex++
		return connection, nil
	}
	t.Cleanup(func() {
		assert.Equal(t, len(connections), connectionIndex, "not all LDAP connections were used")
	})

	return ctx, strategy
}

func newLDAPTestUser() ldapclient.Entry {
	return ldapclient.Entry{
		DN: "CN=Alice Example,OU=Contractors,OU=Users,DC=example,DC=com",
		Attributes: []*ldapclient.EntryAttribute{
			{Name: "sAMAccountName", Values: []string{"alice"}},
			{Name: "employeeID", Values: []string{"12345"}},
		},
	}
}

func TestLDAPGroupSearchFilter_MemberMatcherWithSeparateBaseDN_ShouldUseReturnedUserDN(t *testing.T) {
	// Arrange
	conf := &Configuration{}
	conf.UserSearch.BaseDN = "OU=Users,DC=example,DC=com"
	conf.GroupSearch.Filter = "(objectClass=group)"
	conf.GroupSearch.UserMatchers = []GroupUserMatcher{{
		UserAttr:  "sAMAccountName",
		GroupAttr: "member",
	}}
	user := ldapclient.Entry{
		DN: "CN=Alice Example,OU=Contractors,OU=Users,DC=example,DC=com",
		Attributes: []*ldapclient.EntryAttribute{{
			Name:   "sAMAccountName",
			Values: []string{"alice"},
		}},
	}

	// Act
	filter := ldapGroupSearchFilter(conf, user)

	// Assert
	require.Equal(t, fmt.Sprintf("(&(member=%s)(objectClass=group))", ldapclient.EscapeFilter(user.DN)), filter)
	assert.NotContains(t, filter, "sAMAccountName=alice,OU=Users")
}

func TestLDAPGroupSearchFilter_AttributeMatcher_ShouldUseEscapedAttributeValue(t *testing.T) {
	// Arrange
	conf := newLDAPTestConfiguration()
	conf.GroupSearch.UserMatchers = []GroupUserMatcher{{UserAttr: "employeeID", GroupAttr: "employeeNumber"}}
	user := newLDAPTestUser()
	user.Attributes[1].Values = []string{"12345)(uid=*)"}

	// Act
	filter := ldapGroupSearchFilter(conf, user)

	// Assert
	assert.Equal(t, "(&(employeeNumber=12345\\29\\28uid=\\2a\\29)(objectClass=group))", filter)
}

func TestLDAPLogin_MatcherGroupsWithSeparateBaseDN_ShouldAuthenticateAndReturnGroups(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	user := newLDAPTestUser()
	group := &ldapclient.Entry{DN: "CN=Administrators,OU=Groups,DC=example,DC=com"}
	userSearchClosed := false
	passwordVerificationClosed := false
	groupSearchClosed := false
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig,
		&ldapConnectionMock{
			bindFunc: func(username string, password string) error {
				assert.Equal(t, ldapConfig.BindDN, username)
				assert.Equal(t, ldapConfig.BindPW, password)
				return nil
			},
			closeFunc: func() error {
				userSearchClosed = true
				return nil
			},
			searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
				assert.Equal(t, ldapConfig.UserSearch.BaseDN, searchRequest.BaseDN)
				assert.Equal(t, "(&(sAMAccountName=alice)(objectClass=user))", searchRequest.Filter)
				assert.Equal(t, []string{"sAMAccountName", "givenName", "employeeID"}, searchRequest.Attributes)
				return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&user}}, nil
			},
		},
		&ldapConnectionMock{
			bindFunc: func(username string, password string) error {
				assert.Equal(t, user.DN, username)
				assert.Equal(t, "correct-password", password)
				return nil
			},
			closeFunc: func() error {
				passwordVerificationClosed = true
				return nil
			},
		},
		&ldapConnectionMock{
			bindFunc: func(username string, password string) error {
				assert.Equal(t, ldapConfig.BindDN, username)
				assert.Equal(t, ldapConfig.BindPW, password)
				return nil
			},
			closeFunc: func() error {
				groupSearchClosed = true
				return nil
			},
			searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
				assert.Equal(t, ldapConfig.GroupSearch.BaseDN, searchRequest.BaseDN)
				assert.Equal(t, fmt.Sprintf("(&(member=%s)(objectClass=group))", ldapclient.EscapeFilter(user.DN)), searchRequest.Filter)
				return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{group}}, nil
			},
		},
	)

	// Act
	actualUser, groups, err := strategy.ldapLogin(ctx, "alice", "correct-password")

	// Assert
	require.NoError(t, err)
	assert.Equal(t, user.DN, actualUser.DN)
	require.Len(t, groups, 1)
	assert.Equal(t, group.DN, groups[0].DN)
	assert.True(t, userSearchClosed)
	assert.True(t, passwordVerificationClosed)
	assert.True(t, groupSearchClosed)
}

func TestLDAPLogin_UserDoesNotExist_ShouldReturnUserNotFoundError(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	userSearchClosed := false
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig, &ldapConnectionMock{
		closeFunc: func() error {
			userSearchClosed = true
			return nil
		},
		searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
			return &ldapclient.SearchResult{}, nil
		},
	})

	// Act
	_, groups, err := strategy.ldapLogin(ctx, "missing", "password")

	// Assert
	assert.ErrorIs(t, err, errLDAPUserNotFound)
	assert.Empty(t, groups)
	assert.True(t, userSearchClosed)
}

func TestLDAPLogin_GroupSearchFails_ShouldReturnOperationalError(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	user := newLDAPTestUser()
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig,
		&ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
			return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&user}}, nil
		}},
		&ldapConnectionMock{},
		&ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
			return nil, stderrors.New("directory unavailable")
		}},
	)

	// Act
	_, groups, err := strategy.ldapLogin(ctx, "alice", "correct-password")

	// Assert
	assert.True(t, isLDAPOperationalError(err))
	assert.Empty(t, groups)
	actual := pkgerrors.Cause(ldapLoginError(err)).(*schema.ValidationError)
	expected := pkgerrors.Cause(schema.NewLDAPStatusServiceUnavailable()).(*schema.ValidationError)
	assert.Equal(t, expected.Messages[0].Text, actual.Messages[0].Text)
}

func TestLDAPLogin_InvalidPassword_ShouldReturnInvalidCredentialsError(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	user := newLDAPTestUser()
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig,
		&ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
			return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&user}}, nil
		}},
		&ldapConnectionMock{bindFunc: func(username string, password string) error {
			return ldapclient.NewError(ldapclient.LDAPResultInvalidCredentials, stderrors.New("invalid password"))
		}},
	)

	// Act
	_, groups, err := strategy.ldapLogin(ctx, "alice", "incorrect-password")

	// Assert
	assert.True(t, ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInvalidCredentials))
	assert.False(t, isLDAPOperationalError(err))
	assert.Empty(t, groups)
}

func TestLDAPGroupsFromUserMemberOf_OneKnownAndOneMissingGroup_ShouldReturnKnownGroup(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	ldapConfig.GroupSearch.GroupsFromUserMemberOf = true
	user := newLDAPTestUser()
	user.Attributes = append(user.Attributes, &ldapclient.EntryAttribute{
		Name:   "memberOf",
		Values: []string{"CN=Administrators,OU=Groups,DC=example,DC=com", "CN=Missing,OU=Groups,DC=example,DC=com"},
	})
	knownGroup := &ldapclient.Entry{DN: "CN=Administrators,OU=Groups,DC=example,DC=com"}
	_, strategy := newLDAPTestStrategy(t, ldapConfig,
		&ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
			assert.Equal(t, knownGroup.DN, searchRequest.BaseDN)
			assert.Equal(t, ldapclient.ScopeWholeSubtree, searchRequest.Scope)
			return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{knownGroup}}, nil
		}},
		&ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
			assert.Equal(t, "CN=Missing,OU=Groups,DC=example,DC=com", searchRequest.BaseDN)
			return &ldapclient.SearchResult{}, nil
		}},
	)

	// Act
	groups, err := strategy.ldapGroupsFromUserMemberOf(ldapConfig, user)

	// Assert
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, knownGroup.DN, groups[0].DN)
}

func TestLDAPUserSearchAttributes_MatcherAttributeIsNotIdentityAttribute_ShouldIncludeMatcherAttributeOnce(t *testing.T) {
	// Arrange
	conf := &Configuration{}
	conf.UserSearch.Username = "sAMAccountName"
	conf.UserSearch.IdentityAttributes = []IdentityAttribute{{Name: "firstName", Attr: "givenName"}}
	conf.GroupSearch.UserMatchers = []GroupUserMatcher{
		{UserAttr: "employeeID", GroupAttr: "employeeNumber"},
		{UserAttr: "sAMAccountName", GroupAttr: "memberUid"},
	}

	// Act
	attributes := ldapUserSearchAttributes(conf)

	// Assert
	assert.Equal(t, []string{"sAMAccountName", "givenName", "employeeID"}, attributes)
}

func TestLDAPUserSearchAttributes_GroupsFromMemberOf_ShouldRequestMemberOfAndIgnoreMatchers(t *testing.T) {
	// Arrange
	conf := newLDAPTestConfiguration()
	conf.GroupSearch.GroupsFromUserMemberOf = true

	// Act
	attributes := ldapUserSearchAttributes(conf)

	// Assert
	assert.Equal(t, []string{"sAMAccountName", "memberOf", "givenName"}, attributes)
}

func TestLDAPOperationalError_WrappedFailure_ShouldExposeCause(t *testing.T) {
	// Arrange
	cause := stderrors.New("directory unavailable")

	// Act
	err := newLDAPOperationalError(cause)

	// Assert
	assert.EqualError(t, err, cause.Error())
	assert.ErrorIs(t, err, cause)
	assert.True(t, isLDAPOperationalError(err))
}

func TestDefaultLDAPDialer_MalformedURL_ShouldReturnError(t *testing.T) {
	// Arrange
	ldapURL := "://invalid"

	// Act
	connection, err := defaultLDAPDialer(ldapURL)

	// Assert
	assert.Nil(t, connection)
	assert.Error(t, err)
}

func TestLDAPLoginError_OperationalLDAPFailure_ShouldReturnServiceUnavailableError(t *testing.T) {
	// Arrange
	ldapFailure := newLDAPOperationalError(stderrors.New("group search failed"))

	// Act
	err := ldapLoginError(ldapFailure)

	// Assert
	expected := pkgerrors.Cause(schema.NewLDAPStatusServiceUnavailable()).(*schema.ValidationError)
	actual := pkgerrors.Cause(err).(*schema.ValidationError)
	assert.Equal(t, expected.Messages[0].Text, actual.Messages[0].Text)
}

func TestLDAPLoginError_InvalidLDAPCredentials_ShouldReturnInvalidCredentialsError(t *testing.T) {
	// Arrange
	ldapFailure := ldapclient.NewError(ldapclient.LDAPResultInvalidCredentials, stderrors.New("invalid password"))

	// Act
	err := ldapLoginError(ldapFailure)

	// Assert
	expected := pkgerrors.Cause(schema.NewInvalidCredentialsError()).(*schema.ValidationError)
	actual := pkgerrors.Cause(err).(*schema.ValidationError)
	assert.Equal(t, expected.Messages[0].Text, actual.Messages[0].Text)
}

func TestLDAPLoginError_UserNotFound_ShouldReturnInvalidCredentialsError(t *testing.T) {
	// Arrange
	ldapFailure := errLDAPUserNotFound

	// Act
	err := ldapLoginError(ldapFailure)

	// Assert
	expected := pkgerrors.Cause(schema.NewInvalidCredentialsError()).(*schema.ValidationError)
	actual := pkgerrors.Cause(err).(*schema.ValidationError)
	assert.Equal(t, expected.Messages[0].Text, actual.Messages[0].Text)
}

func TestLDAPLoginError_ConfigurationFailure_ShouldPreserveError(t *testing.T) {
	// Arrange
	configurationFailure := stderrors.New("invalid LDAP configuration")

	// Act
	err := ldapLoginError(configurationFailure)

	// Assert
	assert.ErrorIs(t, err, configurationFailure)
}
