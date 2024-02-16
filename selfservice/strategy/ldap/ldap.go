package ldap

import (
	"context"
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/ory/herodot"
	"github.com/pkg/errors"
)

var noEntry = ldap.Entry{}
var noEntries = []*ldap.Entry{}

func (s *Strategy) ldapLogin(ctx context.Context, username string, password string) (user ldap.Entry, groups []*ldap.Entry, err error) {
	conf, err := s.Config(ctx)
	if err != nil {
		s.d.Logger().WithError(err).Debug("LDAP Config")
		return noEntry, noEntries, err
	}

	found, user, err := s.ldapUserEntry(ctx, username)
	if err != nil {
		return noEntry, noEntries, err
	}

	if !found {
		return noEntry, noEntries, errors.New("User not found")
	}

	l, err := ldap.DialURL(conf.URL)
	if err != nil {
		return noEntry, noEntries, err
	}
	defer l.Close()

	s.d.Logger().WithField("UserDN", user.DN).
		Debug("LDAP User Entry")

	err = l.Bind(user.DN, password)
	if err != nil {
		return noEntry, noEntries, err
	}

	groups, err = s.ldapGroupEntries(ctx, user)
	if err != nil {
		return user, noEntries, nil
	}

	return user, groups, nil
}

func (s *Strategy) ldapUserEntry(ctx context.Context, username string) (found bool, user ldap.Entry, err error) {
	conf, err := s.Config(ctx)
	if err != nil {
		return false, noEntry, err
	}

	filter := fmt.Sprintf("(&(%s=%s)%s)",
		conf.UserSearch.Username,
		ldap.EscapeFilter(username),
		conf.UserSearch.Filter,
	)

	attrs := []string{conf.UserSearch.Username}

	if conf.GroupSearch.GroupsFromUserMemberOf {
		attrs = append(attrs, "memberOf")
	}

	for _, list := range conf.UserSearch.IdentityAttributes {
		attrs = append(attrs, list.Attr)
	}

	req := &ldap.SearchRequest{
		BaseDN:     conf.UserSearch.BaseDN,
		Filter:     filter,
		Scope:      ldap.ScopeWholeSubtree,
		Attributes: attrs,
	}

	l, err := ldap.DialURL(conf.URL)
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

func (s *Strategy) ldapGroupEntries(ctx context.Context, user ldap.Entry) (groups []*ldap.Entry, err error) {
	conf, err := s.Config(ctx)
	if err != nil {
		return noEntries, err
	}

	switch {
	case conf.GroupSearch.GroupsFromUserMemberOf:
		groups, err = s.ldapGroupsFromUserMemberOf(ctx, user)
	default:
		groups, err = s.ldapGroupsUserMatchers(ctx, user)
	}

	return groups, err
}

func (s *Strategy) ldapGroupsFromUserMemberOf(ctx context.Context, user ldap.Entry) (groups []*ldap.Entry, err error) {
	groups = noEntries

	for _, memberOf := range user.GetAttributeValues("memberOf") {
		found, group, err := s.ldapGroupDNEntry(ctx, memberOf)
		if err != nil {
			return noEntries, err
		}

		if found {
			groups = append(groups, &group)
		}
	}

	return groups, nil
}

func (s *Strategy) ldapGroupsUserMatchers(ctx context.Context, user ldap.Entry) (groups []*ldap.Entry, err error) {
	conf, err := s.Config(ctx)
	if err != nil {
		return noEntries, err
	}

	groups = noEntries

	matchFilters := []string{}
	for _, matcher := range conf.GroupSearch.UserMatchers {
		switch matcher.GroupAttr {
		case "uniqueMember", "member":
			matchFilters = append(matchFilters, fmt.Sprintf("(%s=%s=%s,%s)",
				matcher.GroupAttr, matcher.UserAttr, user.GetAttributeValue(matcher.UserAttr), conf.UserSearch.BaseDN),
			)
		default:
			matchFilters = append(matchFilters, fmt.Sprintf("(%s=%s)",
				matcher.GroupAttr, user.GetAttributeValue(matcher.UserAttr)),
			)
		}
	}

	filter := fmt.Sprintf("(&%s%s)", strings.Join(matchFilters[:], ""), conf.GroupSearch.Filter)

	req := &ldap.SearchRequest{
		BaseDN: conf.GroupSearch.BaseDN,
		Filter: filter,
		Scope:  ldap.ScopeWholeSubtree,
	}

	l, err := ldap.DialURL(conf.URL)
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

func (s *Strategy) ldapGroupDNEntry(ctx context.Context, groupDN string) (found bool, group ldap.Entry, err error) {
	conf, err := s.Config(ctx)
	if err != nil {
		return false, noEntry, err
	}

	filter := fmt.Sprintf("(&%s)", conf.GroupSearch.Filter)

	req := &ldap.SearchRequest{
		BaseDN: groupDN,
		Filter: filter,
		Scope:  ldap.ScopeWholeSubtree,
	}

	l, err := ldap.DialURL(conf.URL)
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
