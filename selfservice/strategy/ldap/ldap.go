// Copyright © 2024-2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
)

const (
	ldapPageSize               = 500
	ldapSearchTimeLimitSeconds = 8
	ldapRequestTimeout         = 8 * time.Second
)

var (
	noEntry   = ldapclient.Entry{}
	noEntries []*ldapclient.Entry

	errLDAPUserNotFound       = errors.New("LDAP user not found")
	errLDAPMultipleUsersFound = errors.New("multiple LDAP users found")
)

var dialer = net.Dialer{
	Timeout: 9 * time.Second,
}

type ldapConnection interface {
	Bind(username string, password string) error
	Close() error
	SearchWithPaging(searchRequest *ldapclient.SearchRequest, pagingSize uint32) (*ldapclient.SearchResult, error)
	SetTimeout(timeout time.Duration)
	StartTLS(config *tls.Config) error
}

type ldapDialer func(url string, options ...ldapclient.DialOpt) (ldapConnection, error)

func defaultLDAPDialer(url string, options ...ldapclient.DialOpt) (ldapConnection, error) {
	return ldapclient.DialURL(url, options...)
}

type ldapOperationalError struct {
	cause error
}

func (e *ldapOperationalError) Error() string {
	return e.cause.Error()
}

func (e *ldapOperationalError) Unwrap() error {
	return e.cause
}

func newLDAPOperationalError(cause error) error {
	return &ldapOperationalError{cause: cause}
}

func isLDAPOperationalError(err error) bool {
	var operationalError *ldapOperationalError
	return errors.As(err, &operationalError)
}

func ldapUserSearchAttributes(configuration *Configuration) []string {
	attributes := make([]string, 0, 2+len(configuration.UserSearch.IdentityAttributes)+len(configuration.GroupSearch.UserMatchers))
	addedAttributes := make(map[string]struct{}, cap(attributes))

	addAttribute := func(attribute string) {
		if attribute == "" {
			return
		}
		if _, found := addedAttributes[attribute]; found {
			return
		}

		addedAttributes[attribute] = struct{}{}
		attributes = append(attributes, attribute)
	}

	addAttribute(configuration.UserSearch.Username)

	if configuration.GroupSearch.GroupsFromUserMemberOf {
		addAttribute("memberOf")
	}

	for _, identityAttribute := range configuration.UserSearch.IdentityAttributes {
		addAttribute(identityAttribute.Attr)
	}

	if !configuration.GroupSearch.GroupsFromUserMemberOf {
		for _, matcher := range configuration.GroupSearch.UserMatchers {
			addAttribute(matcher.UserAttr)
		}
	}

	return attributes
}

func ldapGroupSearchAttributes(configuration *Configuration) []string {
	if configuration.GroupSearch.NameAttribute == "" {
		return nil
	}
	return []string{configuration.GroupSearch.NameAttribute}
}

func combineLDAPFilters(filters ...string) string {
	nonEmptyFilters := make([]string, 0, len(filters))
	for _, filter := range filters {
		if strings.TrimSpace(filter) != "" {
			nonEmptyFilters = append(nonEmptyFilters, filter)
		}
	}

	switch len(nonEmptyFilters) {
	case 0:
		return "(objectClass=*)"
	case 1:
		return nonEmptyFilters[0]
	default:
		return fmt.Sprintf("(&%s)", strings.Join(nonEmptyFilters, ""))
	}
}

func ldapGroupSearchFilter(configuration *Configuration, user ldapclient.Entry) (string, error) {
	matchFilters := make([]string, 0, len(configuration.GroupSearch.UserMatchers))
	for _, matcher := range configuration.GroupSearch.UserMatchers {
		switch matcher.GroupAttr {
		case "uniqueMember", "member":
			matchFilters = append(matchFilters, fmt.Sprintf("(%s=%s)", matcher.GroupAttr, ldapclient.EscapeFilter(user.DN)))
		default:
			userAttributeValue := user.GetAttributeValue(matcher.UserAttr)
			if userAttributeValue == "" {
				return "", errors.Errorf("LDAP user result is missing group matcher attribute %q", matcher.UserAttr)
			}
			matchFilters = append(matchFilters, fmt.Sprintf("(%s=%s)", matcher.GroupAttr, ldapclient.EscapeFilter(userAttributeValue)))
		}
	}

	return combineLDAPFilters(append(matchFilters, configuration.GroupSearch.Filter)...), nil
}

func newLDAPSearchRequest(searchBase resolvedLDAPSearchBase, filter string, attributes []string) *ldapclient.SearchRequest {
	return ldapclient.NewSearchRequest(
		searchBase.distinguishedName,
		searchBase.searchScope,
		ldapclient.NeverDerefAliases,
		0,
		ldapSearchTimeLimitSeconds,
		false,
		filter,
		attributes,
		nil,
	)
}

func ldapSearch(connection ldapConnection, request *ldapclient.SearchRequest) ([]*ldapclient.Entry, error) {
	result, err := connection.SearchWithPaging(request, ldapPageSize)
	if err != nil {
		return noEntries, err
	}
	if result == nil {
		return noEntries, errors.New("LDAP search returned no result")
	}

	return result.Entries, nil
}

func (s *Strategy) openLDAPConnection(configuration *Configuration) (ldapConnection, error) {
	dialOptions := []ldapclient.DialOpt{ldapclient.DialWithDialer(&dialer)}
	if configuration.resolvedTLSConfig != nil {
		dialOptions = append(dialOptions, ldapclient.DialWithTLSConfig(configuration.resolvedTLSConfig))
	}

	connection, err := s.ldapDial(configuration.URL, dialOptions...)
	if err != nil {
		return nil, err
	}
	connection.SetTimeout(ldapRequestTimeout)

	if configuration.resolvedTLSMode == ldapTLSModeStartTLS {
		// A failed upgrade must fail the connection. Continuing on the plaintext
		// connection would turn a configured StartTLS into a silent downgrade.
		if err := connection.StartTLS(configuration.resolvedTLSConfig); err != nil {
			s.closeLDAPConnection(connection)
			return nil, errors.Wrap(err, "could not upgrade the LDAP connection using StartTLS")
		}
	}

	return connection, nil
}

func (s *Strategy) closeLDAPConnection(connection ldapConnection) {
	if err := connection.Close(); err != nil {
		s.d.Logger().WithError(err).Debug("Could not close LDAP connection")
	}
}

func (s *Strategy) ldapLogin(ctx context.Context, username string, password string) (user ldapclient.Entry, groups []*ldapclient.Entry, err error) {
	configuration, err := s.Config(ctx)
	if err != nil {
		s.d.Logger().WithError(err).Debug("LDAP Config")
		return noEntry, noEntries, err
	}

	serviceConnection, err := s.openLDAPConnection(configuration)
	if err != nil {
		return noEntry, noEntries, newLDAPOperationalError(err)
	}
	defer s.closeLDAPConnection(serviceConnection)

	if err := serviceConnection.Bind(configuration.BindDN, configuration.BindPW); err != nil {
		return noEntry, noEntries, newLDAPOperationalError(err)
	}

	found, user, err := s.ldapUserEntry(configuration, serviceConnection, username)
	if err != nil {
		if errors.Is(err, errLDAPMultipleUsersFound) {
			return noEntry, noEntries, err
		}
		return noEntry, noEntries, newLDAPOperationalError(err)
	}
	if !found {
		return noEntry, noEntries, errLDAPUserNotFound
	}

	s.d.Logger().WithField("UserDN", user.DN).Debug("LDAP User Entry")

	if err := s.verifyLDAPPassword(configuration, user.DN, password); err != nil {
		if ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInvalidCredentials) {
			return noEntry, noEntries, err
		}
		return noEntry, noEntries, newLDAPOperationalError(err)
	}

	groups, err = s.ldapGroupEntries(configuration, serviceConnection, user)
	if err != nil {
		return user, noEntries, newLDAPOperationalError(err)
	}

	return user, groups, nil
}

func (s *Strategy) verifyLDAPPassword(configuration *Configuration, userDN string, password string) error {
	connection, err := s.openLDAPConnection(configuration)
	if err != nil {
		return err
	}
	defer s.closeLDAPConnection(connection)

	return connection.Bind(userDN, password)
}

func (s *Strategy) ldapUserEntry(configuration *Configuration, connection ldapConnection, username string) (found bool, user ldapclient.Entry, err error) {
	filter := combineLDAPFilters(
		fmt.Sprintf("(%s=%s)", configuration.UserSearch.Username, ldapclient.EscapeFilter(username)),
		configuration.UserSearch.Filter,
	)
	searchBases, err := resolveLDAPSearchBases(configuration.UserSearch.BaseDN, configuration.UserSearch.BaseDNs)
	if err != nil {
		return false, noEntry, err
	}

	var foundUser *ldapclient.Entry
	for _, searchBase := range searchBases {
		entries, err := ldapSearch(connection, newLDAPSearchRequest(searchBase, filter, ldapUserSearchAttributes(configuration)))
		if err != nil {
			return false, noEntry, errors.Wrapf(err, "could not search for LDAP user %q", username)
		}

		for _, entry := range entries {
			if foundUser != nil {
				return false, noEntry, errors.Wrapf(errLDAPMultipleUsersFound, "username %q", username)
			}
			foundUser = entry
		}
	}

	if foundUser == nil {
		return false, noEntry, nil
	}

	return true, *foundUser, nil
}

func (s *Strategy) ldapGroupEntries(configuration *Configuration, connection ldapConnection, user ldapclient.Entry) ([]*ldapclient.Entry, error) {
	if configuration.GroupSearch.GroupsFromUserMemberOf {
		return s.ldapGroupsFromUserMemberOf(configuration, connection, user)
	}

	return s.ldapGroupsUserMatchers(configuration, connection, user)
}

func (s *Strategy) ldapGroupsFromUserMemberOf(configuration *Configuration, connection ldapConnection, user ldapclient.Entry) ([]*ldapclient.Entry, error) {
	memberOfValues := uniqueStringsFold(user.GetAttributeValues("memberOf"))
	if len(memberOfValues) == 0 {
		return noEntries, nil
	}

	groups := make([]*ldapclient.Entry, 0, len(memberOfValues))
	filter := combineLDAPFilters(configuration.GroupSearch.Filter)
	for _, groupDN := range memberOfValues {
		searchBase := resolvedLDAPSearchBase{
			distinguishedName: groupDN,
			searchScope:       ldapclient.ScopeBaseObject,
		}
		entries, err := ldapSearch(connection, newLDAPSearchRequest(searchBase, filter, ldapGroupSearchAttributes(configuration)))
		if err != nil {
			return noEntries, errors.Wrapf(err, "could not resolve LDAP memberOf group %q", groupDN)
		}
		if len(entries) > 1 {
			return noEntries, errors.Errorf("found multiple LDAP groups for memberOf distinguished name %q", groupDN)
		}
		if len(entries) == 1 {
			groups = append(groups, entries[0])
		}
	}

	return groups, nil
}

func (s *Strategy) ldapGroupsUserMatchers(configuration *Configuration, connection ldapConnection, user ldapclient.Entry) ([]*ldapclient.Entry, error) {
	filter, err := ldapGroupSearchFilter(configuration, user)
	if err != nil {
		return noEntries, err
	}
	searchBases, err := resolveLDAPSearchBases(configuration.GroupSearch.BaseDN, configuration.GroupSearch.BaseDNs)
	if err != nil {
		return noEntries, err
	}

	groups := make([]*ldapclient.Entry, 0)
	seenGroupDNs := make(map[string]struct{})
	for _, searchBase := range searchBases {
		entries, err := ldapSearch(connection, newLDAPSearchRequest(searchBase, filter, ldapGroupSearchAttributes(configuration)))
		if err != nil {
			return noEntries, errors.Wrapf(err, "could not search LDAP groups using matchers %#v", configuration.GroupSearch.UserMatchers)
		}
		groups = appendUniqueLDAPEntries(groups, seenGroupDNs, entries)
	}

	return groups, nil
}

func uniqueStringsFold(values []string) []string {
	uniqueValues := make([]string, 0, len(values))
	seenValues := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := strings.ToLower(value)
		if _, found := seenValues[key]; found {
			continue
		}
		seenValues[key] = struct{}{}
		uniqueValues = append(uniqueValues, value)
	}
	return uniqueValues
}

func appendUniqueLDAPEntries(existingEntries []*ldapclient.Entry, seenEntryDNs map[string]struct{}, entries []*ldapclient.Entry) []*ldapclient.Entry {
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		entryDN := strings.ToLower(entry.DN)
		if _, found := seenEntryDNs[entryDN]; found {
			continue
		}
		seenEntryDNs[entryDN] = struct{}{}
		existingEntries = append(existingEntries, entry)
	}
	return existingEntries
}
