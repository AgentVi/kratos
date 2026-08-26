package ldap

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/ory/herodot"
	"github.com/pkg/errors"
)

var noEntry = ldap.Entry{}
var noEntries []*ldap.Entry

// errLDAPUserNotFound keeps an unknown directory user indistinguishable from an invalid password at the login boundary.
var errLDAPUserNotFound = errors.New("LDAP user not found")

var dialer = net.Dialer{
	Timeout: 9 * time.Second, // The default write timeout for the http.Server (see serve.go) is 10 seconds so time need to be lesser than that to handel error message.
}
var dailOpts = ldap.DialWithDialer(&dialer)

// ldapConnection is the small portion of an LDAP connection used by this strategy.
// Keeping the directory transport behind this interface lets the login flow be
// exercised without requiring a live LDAP server.
type ldapConnection interface {
	Bind(username string, password string) error
	Close() error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
}

// ldapDialer creates the connections used for user lookup, password verification,
// and group lookup. Production strategies use defaultLDAPDialer.
type ldapDialer func(url string, options ...ldap.DialOpt) (ldapConnection, error)

func defaultLDAPDialer(url string, options ...ldap.DialOpt) (ldapConnection, error) {
	return ldap.DialURL(url, options...)
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

// ldapUserSearchAttributes collects every user attribute needed after the user search.
// Matchers may use an attribute that is neither the username nor an identity trait,
// so it must be requested explicitly before group resolution begins.
func ldapUserSearchAttributes(conf *Configuration) []string {
	attributes := make([]string, 0, 2+len(conf.UserSearch.IdentityAttributes)+len(conf.GroupSearch.UserMatchers))
	addedAttributes := make(map[string]struct{}, cap(attributes))

	addAttribute := func(attribute string) {
		if _, found := addedAttributes[attribute]; found {
			return
		}

		addedAttributes[attribute] = struct{}{}
		attributes = append(attributes, attribute)
	}

	addAttribute(conf.UserSearch.Username)

	if conf.GroupSearch.GroupsFromUserMemberOf {
		addAttribute("memberOf")
	}

	for _, identityAttribute := range conf.UserSearch.IdentityAttributes {
		addAttribute(identityAttribute.Attr)
	}

	if !conf.GroupSearch.GroupsFromUserMemberOf {
		for _, matcher := range conf.GroupSearch.UserMatchers {
			addAttribute(matcher.UserAttr)
		}
	}

	return attributes
}

func ldapGroupSearchFilter(conf *Configuration, user ldap.Entry) string {
	matchFilters := make([]string, 0, len(conf.GroupSearch.UserMatchers))
	for _, matcher := range conf.GroupSearch.UserMatchers {
		switch matcher.GroupAttr {
		case "uniqueMember", "member":
			// LDAP group membership attributes contain the complete distinguished name,
			// including any nested user OUs. Rebuilding it from user_search.base_dn
			// breaks installations where users and groups use separate branches.
			matchFilters = append(matchFilters, fmt.Sprintf("(%s=%s)", matcher.GroupAttr, ldap.EscapeFilter(user.DN)))
		default:
			matchFilters = append(matchFilters, fmt.Sprintf("(%s=%s)", matcher.GroupAttr, ldap.EscapeFilter(user.GetAttributeValue(matcher.UserAttr))))
		}
	}

	return fmt.Sprintf("(&%s%s)", strings.Join(matchFilters, ""), conf.GroupSearch.Filter)
}

func (s *Strategy) ldapLogin(ctx context.Context, username string, password string) (user ldap.Entry, groups []*ldap.Entry, err error) {
	// Use one configuration snapshot for user lookup, password verification, and group lookup.
	conf, err := s.Config(ctx)
	if err != nil {
		s.d.Logger().WithError(err).Debug("LDAP Config")
		return noEntry, noEntries, err
	}

	found, user, err := s.ldapUserEntry(conf, username)
	if err != nil {
		return noEntry, noEntries, newLDAPOperationalError(err)
	}

	if !found {
		return noEntry, noEntries, errLDAPUserNotFound
	}

	l, err := s.ldapDial(conf.URL, dailOpts)
	if err != nil {
		return noEntry, noEntries, newLDAPOperationalError(err)
	}
	defer func(l ldapConnection) {
		err := l.Close()
		if err != nil {

		}
	}(l)

	s.d.Logger().WithField("UserDN", user.DN).
		Debug("LDAP User Entry")

	err = l.Bind(user.DN, password)
	if err != nil {
		// An invalid bind is an authentication failure. Any other bind result means
		// the directory could not complete the login and must not look like bad credentials.
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return noEntry, noEntries, newLDAPOperationalError(err)
		}

		return noEntry, noEntries, err
	}

	groups, err = s.ldapGroupEntries(conf, user)
	if err != nil {
		// Do not continue with a partial result: callers may refresh stored traits
		// from this group list, so an LDAP failure must never become an empty list.
		return user, noEntries, newLDAPOperationalError(err)
	}

	return user, groups, nil
}

func (s *Strategy) ldapUserEntry(conf *Configuration, username string) (found bool, user ldap.Entry, err error) {
	filter := fmt.Sprintf("(&(%s=%s)%s)",
		conf.UserSearch.Username,
		ldap.EscapeFilter(username),
		conf.UserSearch.Filter,
	)

	req := &ldap.SearchRequest{
		BaseDN:     conf.UserSearch.BaseDN,
		Filter:     filter,
		Scope:      ldap.ScopeWholeSubtree,
		Attributes: ldapUserSearchAttributes(conf),
	}

	l, err := s.ldapDial(conf.URL, dailOpts)
	if err != nil {
		return false, noEntry, err
	}
	defer func(l ldapConnection) {
		err := l.Close()
		if err != nil {

		}
	}(l)

	if err = l.Bind(conf.BindDN, conf.BindPW); err != nil {
		return false, noEntry, err
	}

	resp, err := l.Search(req)
	if err != nil {
		err = errors.WithStack(herodot.ErrBadRequest.
			WithReasonf("Could not search for the identity: %s", ldap.EscapeFilter(username)).WithDebug(err.Error()))
		s.d.Logger().WithError(err)
		return false, noEntry, err
	}

	switch n := len(resp.Entries); n {
	case 0:
		return false, noEntry, nil
	case 1:
		user = *resp.Entries[0]
		return true, user, nil
	default:
		err = errors.WithStack(herodot.ErrBadRequest.
			WithReasonf("Found multiple entries: %s", ldap.EscapeFilter(username)).WithDebug(err.Error()))
		return false, noEntry, err
	}
}

func (s *Strategy) ldapGroupEntries(conf *Configuration, user ldap.Entry) (groups []*ldap.Entry, err error) {
	switch {
	case conf.GroupSearch.GroupsFromUserMemberOf:
		groups, err = s.ldapGroupsFromUserMemberOf(conf, user)
	default:
		groups, err = s.ldapGroupsUserMatchers(conf, user)
	}

	return groups, err
}

func (s *Strategy) ldapGroupsFromUserMemberOf(conf *Configuration, user ldap.Entry) (groups []*ldap.Entry, err error) {
	groups = noEntries

	for _, memberOf := range user.GetAttributeValues("memberOf") {
		found, group, err := s.ldapGroupDNEntry(conf, memberOf)
		if err != nil {
			return noEntries, err
		}

		if found {
			groups = append(groups, &group)
		}
	}

	return groups, nil
}

func (s *Strategy) ldapGroupsUserMatchers(conf *Configuration, user ldap.Entry) (groups []*ldap.Entry, err error) {
	groups = noEntries

	req := &ldap.SearchRequest{
		BaseDN: conf.GroupSearch.BaseDN,
		Filter: ldapGroupSearchFilter(conf, user),
		Scope:  ldap.ScopeWholeSubtree,
	}

	l, err := s.ldapDial(conf.URL, dailOpts)
	if err != nil {
		return noEntries, err
	}
	defer l.Close()

	if err = l.Bind(conf.BindDN, conf.BindPW); err != nil {
		return noEntries, err
	}

	resp, err := l.Search(req)
	if err != nil {
		err = errors.WithStack(herodot.ErrBadRequest.
			WithReasonf("Could not search for the identity: %#v", conf.GroupSearch.UserMatchers).WithDebug(err.Error()))
		s.d.Logger().WithError(err)
		return noEntries, err
	}

	return resp.Entries, nil
}

func (s *Strategy) ldapGroupDNEntry(conf *Configuration, groupDN string) (found bool, group ldap.Entry, err error) {
	filter := fmt.Sprintf("(&%s)", conf.GroupSearch.Filter)

	req := &ldap.SearchRequest{
		BaseDN: groupDN,
		Filter: filter,
		Scope:  ldap.ScopeWholeSubtree,
	}

	l, err := s.ldapDial(conf.URL, dailOpts)
	if err != nil {
		return false, noEntry, err
	}
	defer l.Close()

	if err = l.Bind(conf.BindDN, conf.BindPW); err != nil {
		return false, noEntry, err
	}

	resp, err := l.Search(req)
	if err != nil {
		err = errors.WithStack(herodot.ErrBadRequest.
			WithReasonf("Could not search for the identity: %s", groupDN).WithDebug(err.Error()))
		s.d.Logger().WithError(err)
		return false, noEntry, err
	}

	switch n := len(resp.Entries); n {
	case 0:
		return false, noEntry, nil
	case 1:
		group = *resp.Entries[0]
		return true, group, nil
	default:
		err = errors.WithStack(herodot.ErrBadRequest.
			WithReasonf("Found multiple entries: %s", groupDN).WithDebug(err.Error()))
		return false, noEntry, err
	}
}
