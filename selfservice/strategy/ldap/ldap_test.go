package ldap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"testing"
	"time"

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
	bindFunc       func(username string, password string) error
	closeFunc      func() error
	searchFunc     func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error)
	setTimeoutFunc func(timeout time.Duration)
	startTLSFunc   func(config *tls.Config) error
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

func (m *ldapConnectionMock) SearchWithPaging(searchRequest *ldapclient.SearchRequest, pagingSize uint32) (*ldapclient.SearchResult, error) {
	if pagingSize != ldapPageSize {
		return nil, fmt.Errorf("unexpected LDAP page size: %d", pagingSize)
	}
	if m.searchFunc == nil {
		return &ldapclient.SearchResult{}, nil
	}

	return m.searchFunc(searchRequest)
}

func (m *ldapConnectionMock) SetTimeout(timeout time.Duration) {
	if m.setTimeoutFunc != nil {
		m.setTimeoutFunc(timeout)
	}
}

func (m *ldapConnectionMock) StartTLS(config *tls.Config) error {
	if m.startTLSFunc == nil {
		return nil
	}

	return m.startTLSFunc(config)
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
	filter, err := ldapGroupSearchFilter(conf, user)

	// Assert
	require.NoError(t, err)
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
	filter, err := ldapGroupSearchFilter(conf, user)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "(&(employeeNumber=12345\\29\\28uid=\\2a\\29)(objectClass=group))", filter)
}

func TestLDAPLogin_MatcherGroupsWithSeparateBaseDN_ShouldAuthenticateAndReturnGroups(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	user := newLDAPTestUser()
	group := &ldapclient.Entry{DN: "CN=Administrators,OU=Groups,DC=example,DC=com"}
	serviceConnectionClosed := false
	passwordVerificationClosed := false
	searchCount := 0
	timeoutCount := 0
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig,
		&ldapConnectionMock{
			bindFunc: func(username string, password string) error {
				assert.Equal(t, ldapConfig.BindDN, username)
				assert.Equal(t, ldapConfig.BindPW, password)
				return nil
			},
			closeFunc: func() error {
				serviceConnectionClosed = true
				return nil
			},
			setTimeoutFunc: func(timeout time.Duration) {
				assert.Equal(t, ldapRequestTimeout, timeout)
				timeoutCount++
			},
			searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
				searchCount++
				assert.Equal(t, ldapSearchTimeLimitSeconds, searchRequest.TimeLimit)
				switch searchCount {
				case 1:
					assert.Equal(t, ldapConfig.UserSearch.BaseDN, searchRequest.BaseDN)
					assert.Equal(t, "(&(sAMAccountName=alice)(objectClass=user))", searchRequest.Filter)
					assert.Equal(t, []string{"sAMAccountName", "givenName", "employeeID"}, searchRequest.Attributes)
					return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&user}}, nil
				case 2:
					assert.Equal(t, ldapConfig.GroupSearch.BaseDN, searchRequest.BaseDN)
					assert.Equal(t, fmt.Sprintf("(&(member=%s)(objectClass=group))", ldapclient.EscapeFilter(user.DN)), searchRequest.Filter)
					return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{group}}, nil
				default:
					return nil, stderrors.New("unexpected search")
				}
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
			setTimeoutFunc: func(timeout time.Duration) {
				assert.Equal(t, ldapRequestTimeout, timeout)
				timeoutCount++
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
	assert.True(t, serviceConnectionClosed)
	assert.True(t, passwordVerificationClosed)
	assert.Equal(t, 2, searchCount)
	assert.Equal(t, 2, timeoutCount)
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
	searchCount := 0
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig,
		&ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
			searchCount++
			if searchCount == 1 {
				return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&user}}, nil
			}
			return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{{DN: "CN=Partial"}}}, stderrors.New("directory unavailable")
		}},
		&ldapConnectionMock{},
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
	knownGroupDN := "CN=Administrators,OU=External,DC=example,DC=com"
	missingGroupDN := "CN=Missing,OU=Another Branch,DC=example,DC=com"
	user.Attributes = append(user.Attributes, &ldapclient.EntryAttribute{
		Name:   "memberOf",
		Values: []string{knownGroupDN, missingGroupDN},
	})
	knownGroup := &ldapclient.Entry{DN: knownGroupDN}
	_, strategy := newLDAPTestStrategy(t, ldapConfig)
	searchCount := 0
	connection := &ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
		searchCount++
		assert.Equal(t, ldapclient.ScopeBaseObject, searchRequest.Scope)
		assert.Equal(t, "(objectClass=group)", searchRequest.Filter)
		if searchRequest.BaseDN == knownGroupDN {
			return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{knownGroup}}, nil
		}
		assert.Equal(t, missingGroupDN, searchRequest.BaseDN)
		return &ldapclient.SearchResult{}, nil
	}}

	// Act
	groups, err := strategy.ldapGroupsFromUserMemberOf(ldapConfig, connection, user)

	// Assert
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, knownGroup.DN, groups[0].DN)
	assert.Equal(t, 2, searchCount)
}

func TestLDAPGroupsFromUserMemberOf_DuplicateDNs_ShouldSearchEachUniqueDNOnce(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	ldapConfig.GroupSearch.GroupsFromUserMemberOf = true
	ldapConfig.GroupSearch.Filter = ""
	user := newLDAPTestUser()
	groupDN := "CN=Administrators,OU=External,DC=example,DC=com"
	user.Attributes = append(user.Attributes, &ldapclient.EntryAttribute{
		Name:   "memberOf",
		Values: []string{groupDN, "cn=administrators,ou=external,dc=example,dc=com"},
	})
	searchCount := 0
	connection := &ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
		searchCount++
		assert.Equal(t, groupDN, searchRequest.BaseDN)
		assert.Equal(t, ldapclient.ScopeBaseObject, searchRequest.Scope)
		assert.Equal(t, "(objectClass=*)", searchRequest.Filter)
		return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{{DN: groupDN}}}, nil
	}}
	_, strategy := newLDAPTestStrategy(t, ldapConfig)

	// Act
	groups, err := strategy.ldapGroupsFromUserMemberOf(ldapConfig, connection, user)

	// Assert
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, groupDN, groups[0].DN)
	assert.Equal(t, 1, searchCount)
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

func TestCombineLDAPFilters_NoConfiguredFilters_ShouldReturnMatchAllFilter(t *testing.T) {
	// Arrange
	filters := []string{"", "   "}

	// Act
	filter := combineLDAPFilters(filters...)

	// Assert
	assert.Equal(t, "(objectClass=*)", filter)
}

func TestLDAPGroupSearchFilter_MissingMatcherAttribute_ShouldReturnError(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	ldapConfig.GroupSearch.UserMatchers = []GroupUserMatcher{{
		UserAttr:  "missingAttribute",
		GroupAttr: "employeeNumber",
	}}
	user := newLDAPTestUser()

	// Act
	_, err := ldapGroupSearchFilter(ldapConfig, user)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missingAttribute")
}

func TestLDAPSearch_PartialResultWithError_ShouldDiscardEntries(t *testing.T) {
	// Arrange
	partialEntry := &ldapclient.Entry{DN: "CN=Partial,DC=example,DC=com"}
	connection := &ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
		return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{partialEntry}}, stderrors.New("size limit exceeded")
	}}
	request := newLDAPSearchRequest(resolvedLDAPSearchBase{
		distinguishedName: "DC=example,DC=com",
		searchScope:       ldapclient.ScopeWholeSubtree,
	}, "(objectClass=*)", nil)

	// Act
	entries, err := ldapSearch(connection, request)

	// Assert
	require.Error(t, err)
	assert.Empty(t, entries)
}

func TestResolveLDAPSearchBases_MultipleBases_ShouldResolveScopes(t *testing.T) {
	// Arrange
	configuredBases := []ldapSearchBase{
		{DistinguishedName: "OU=Employees,DC=example,DC=com"},
		{DistinguishedName: "OU=Contractors,DC=example,DC=com", SearchScope: ldapScopeSingleLevel},
		{DistinguishedName: "CN=Service,DC=example,DC=com", SearchScope: ldapScopeBaseObject},
	}

	// Act
	searchBases, err := resolveLDAPSearchBases("", configuredBases)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, []resolvedLDAPSearchBase{
		{distinguishedName: configuredBases[0].DistinguishedName, searchScope: ldapclient.ScopeWholeSubtree},
		{distinguishedName: configuredBases[1].DistinguishedName, searchScope: ldapclient.ScopeSingleLevel},
		{distinguishedName: configuredBases[2].DistinguishedName, searchScope: ldapclient.ScopeBaseObject},
	}, searchBases)
}

func TestResolveLDAPSearchBases_LegacyAndMultipleBases_ShouldReturnError(t *testing.T) {
	// Arrange
	configuredBases := []ldapSearchBase{{DistinguishedName: "OU=Employees,DC=example,DC=com"}}

	// Act
	_, err := resolveLDAPSearchBases("DC=example,DC=com", configuredBases)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be configured together")
}

func TestLDAPUserEntry_MultipleSearchBasesWithDuplicateUsername_ShouldReturnError(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	ldapConfig.UserSearch.BaseDN = ""
	ldapConfig.UserSearch.BaseDNs = []ldapSearchBase{
		{DistinguishedName: "OU=Employees,DC=example,DC=com"},
		{DistinguishedName: "OU=Contractors,DC=example,DC=com", SearchScope: ldapScopeSingleLevel},
	}
	firstUser := newLDAPTestUser()
	secondUser := newLDAPTestUser()
	secondUser.DN = "CN=Alice Example,OU=Employees,DC=example,DC=com"
	searchCount := 0
	connection := &ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
		searchCount++
		if searchCount == 1 {
			assert.Equal(t, ldapclient.ScopeWholeSubtree, searchRequest.Scope)
			return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&firstUser}}, nil
		}
		assert.Equal(t, ldapclient.ScopeSingleLevel, searchRequest.Scope)
		return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&secondUser}}, nil
	}}
	_, strategy := newLDAPTestStrategy(t, ldapConfig)

	// Act
	found, _, err := strategy.ldapUserEntry(ldapConfig, connection, "alice")

	// Assert
	require.Error(t, err)
	assert.ErrorIs(t, err, errLDAPMultipleUsersFound)
	assert.False(t, found)
	assert.Equal(t, 2, searchCount)
}

func TestLDAPGroupsUserMatchers_MultipleSearchBases_ShouldDeduplicateGroups(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	ldapConfig.GroupSearch.BaseDN = ""
	ldapConfig.GroupSearch.BaseDNs = []ldapSearchBase{
		{DistinguishedName: "OU=Security,DC=example,DC=com"},
		{DistinguishedName: "OU=Distribution,DC=example,DC=com"},
	}
	group := &ldapclient.Entry{DN: "CN=Administrators,OU=Security,DC=example,DC=com"}
	searchCount := 0
	connection := &ldapConnectionMock{searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
		searchCount++
		return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{group}}, nil
	}}
	_, strategy := newLDAPTestStrategy(t, ldapConfig)

	// Act
	groups, err := strategy.ldapGroupsUserMatchers(ldapConfig, connection, newLDAPTestUser())

	// Assert
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, group.DN, groups[0].DN)
	assert.Equal(t, 2, searchCount)
}

func TestLDAPLogin_MultipleUsers_ShouldReturnInvalidCredentialsWithoutPanic(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	firstUser := newLDAPTestUser()
	secondUser := newLDAPTestUser()
	secondUser.DN = "CN=Other Alice,OU=Users,DC=example,DC=com"
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig, &ldapConnectionMock{
		searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
			return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&firstUser, &secondUser}}, nil
		},
	})

	// Act
	_, groups, err := strategy.ldapLogin(ctx, "alice", "password")

	// Assert
	require.Error(t, err)
	assert.ErrorIs(t, err, errLDAPMultipleUsersFound)
	assert.Empty(t, groups)
	expected := pkgerrors.Cause(schema.NewInvalidCredentialsError()).(*schema.ValidationError)
	actual := pkgerrors.Cause(ldapLoginError(err)).(*schema.ValidationError)
	assert.Equal(t, expected.Messages[0].Text, actual.Messages[0].Text)
}

func TestLDAPConfig_MultipleSearchBases_ShouldDecode(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	ldapConfig.UserSearch.BaseDN = ""
	ldapConfig.UserSearch.BaseDNs = []ldapSearchBase{{
		DistinguishedName: "OU=Employees,DC=example,DC=com",
		SearchScope:       ldapScopeSingleLevel,
	}}
	ldapConfig.GroupSearch.BaseDN = ""
	ldapConfig.GroupSearch.BaseDNs = []ldapSearchBase{{
		DistinguishedName: "OU=Groups,DC=example,DC=com",
	}}
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig)

	// Act
	decodedConfiguration, err := strategy.Config(ctx)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, ldapConfig.UserSearch.BaseDNs, decodedConfiguration.UserSearch.BaseDNs)
	assert.Equal(t, ldapConfig.GroupSearch.BaseDNs, decodedConfiguration.GroupSearch.BaseDNs)
}

func TestOpenLDAPConnection_ConfiguredTLS_ShouldDialWithTLSConfiguration(t *testing.T) {
	for ldapURL, expectedDialOptions := range map[string]int{
		// The dialer is always passed, the TLS configuration only when the
		// connection is encrypted.
		"ldap://directory.example.test":  1,
		"ldaps://directory.example.test": 2,
	} {
		t.Run(ldapURL, func(t *testing.T) {
			// Arrange
			ldapConfig := newLDAPTestConfiguration()
			ldapConfig.URL = ldapURL
			require.NoError(t, ldapConfig.resolveTLS())
			dialOptionCount := 0
			strategy := &Strategy{ldapDial: func(url string, options ...ldapclient.DialOpt) (ldapConnection, error) {
				assert.Equal(t, ldapURL, url)
				dialOptionCount = len(options)
				return &ldapConnectionMock{}, nil
			}}

			// Act
			connection, err := strategy.openLDAPConnection(ldapConfig)

			// Assert
			require.NoError(t, err)
			require.NotNil(t, connection)
			assert.Equal(t, expectedDialOptions, dialOptionCount)
		})
	}
}

func TestOpenLDAPConnection_NonStartTLSMode_ShouldNotUpgradeConnection(t *testing.T) {
	for _, ldapURL := range []string{"ldap://directory.example.test", "ldaps://directory.example.test"} {
		t.Run(ldapURL, func(t *testing.T) {
			// Arrange
			ldapConfig := newLDAPTestConfiguration()
			ldapConfig.URL = ldapURL
			require.NoError(t, ldapConfig.resolveTLS())
			startTLSCalled := false
			connection := &ldapConnectionMock{startTLSFunc: func(config *tls.Config) error {
				startTLSCalled = true
				return nil
			}}
			strategy := &Strategy{ldapDial: func(url string, options ...ldapclient.DialOpt) (ldapConnection, error) {
				return connection, nil
			}}

			// Act
			_, err := strategy.openLDAPConnection(ldapConfig)

			// Assert
			require.NoError(t, err)
			assert.False(t, startTLSCalled)
		})
	}
}

func TestLDAPLogin_StartTLSMode_ShouldUpgradeEveryConnectionBeforeBinding(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	ldapConfig.TLS.Mode = ldapTLSModeStartTLS
	user := newLDAPTestUser()
	group := &ldapclient.Entry{DN: "CN=Administrators,OU=Groups,DC=example,DC=com"}
	var serviceOperations, passwordVerificationOperations []string
	serviceConnection := &ldapConnectionMock{
		startTLSFunc: func(config *tls.Config) error {
			assert.NotNil(t, config, "StartTLS must receive the resolved TLS configuration")
			serviceOperations = append(serviceOperations, "starttls")
			return nil
		},
		bindFunc: func(username string, password string) error {
			serviceOperations = append(serviceOperations, "bind")
			return nil
		},
		searchFunc: func(searchRequest *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
			serviceOperations = append(serviceOperations, "search")
			if searchRequest.BaseDN == ldapConfig.UserSearch.BaseDN {
				return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{&user}}, nil
			}
			return &ldapclient.SearchResult{Entries: []*ldapclient.Entry{group}}, nil
		},
	}
	passwordVerificationConnection := &ldapConnectionMock{
		startTLSFunc: func(config *tls.Config) error {
			passwordVerificationOperations = append(passwordVerificationOperations, "starttls")
			return nil
		},
		bindFunc: func(username string, password string) error {
			assert.Equal(t, user.DN, username)
			passwordVerificationOperations = append(passwordVerificationOperations, "bind")
			return nil
		},
	}
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig, serviceConnection, passwordVerificationConnection)

	// Act
	resolvedUser, groups, err := strategy.ldapLogin(ctx, "alice", "password")

	// Assert
	require.NoError(t, err)
	assert.Equal(t, user.DN, resolvedUser.DN)
	require.Len(t, groups, 1)
	assert.Equal(t, []string{"starttls", "bind", "search", "search"}, serviceOperations)
	assert.Equal(t, []string{"starttls", "bind"}, passwordVerificationOperations)
}

func TestLDAPLogin_StartTLSFailure_ShouldFailClosedWithoutBinding(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	ldapConfig.TLS.Mode = ldapTLSModeStartTLS
	startTLSFailure := stderrors.New("server does not support StartTLS")
	connectionClosed := false
	bound := false
	connection := &ldapConnectionMock{
		startTLSFunc: func(config *tls.Config) error {
			return startTLSFailure
		},
		bindFunc: func(username string, password string) error {
			bound = true
			return nil
		},
		closeFunc: func() error {
			connectionClosed = true
			return nil
		},
	}
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig, connection)

	// Act
	_, _, err := strategy.ldapLogin(ctx, "alice", "password")

	// Assert
	require.Error(t, err)
	assert.ErrorIs(t, err, startTLSFailure)
	assert.True(t, isLDAPOperationalError(err))
	assert.False(t, bound, "the connection must not be used after a failed StartTLS upgrade")
	assert.True(t, connectionClosed)
	expected := pkgerrors.Cause(schema.NewLDAPStatusServiceUnavailable()).(*schema.ValidationError)
	actual := pkgerrors.Cause(ldapLoginError(err)).(*schema.ValidationError)
	assert.Equal(t, expected.Messages[0].Text, actual.Messages[0].Text)
}
