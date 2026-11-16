// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"crypto/tls"
	"strings"
	"sync"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
)

// FakeDirectoryUser is a user of a FakeDirectory.
type FakeDirectoryUser struct {
	DN       string
	Password string
}

// FakeDirectory is an in-memory LDAP directory for tests in other packages.
// Users are found by `(<username attribute>=<name>)` below UserBaseDN, group
// searches find nothing.
type FakeDirectory struct {
	ServiceDN         string
	ServicePassword   string
	UserBaseDN        string
	UsernameAttribute string

	mu          sync.Mutex
	users       map[string]FakeDirectoryUser
	unavailable bool
}

func (d *FakeDirectory) SetUser(username string, u FakeDirectoryUser) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.users == nil {
		d.users = map[string]FakeDirectoryUser{}
	}
	d.users[username] = u
}

func (d *FakeDirectory) SetUnavailable(unavailable bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.unavailable = unavailable
}

// UseFakeDirectory makes the strategy talk to d instead of a real directory.
func UseFakeDirectory(s *Strategy, d *FakeDirectory) {
	s.ldapDial = func(string, ...ldapclient.DialOpt) (ldapConnection, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.unavailable {
			return nil, errors.New("dial tcp: connection refused")
		}
		return &fakeDirectoryConnection{d: d}, nil
	}
}

type fakeDirectoryConnection struct {
	d *FakeDirectory
}

func (c *fakeDirectoryConnection) Bind(dn, password string) error {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	if dn == c.d.ServiceDN && password == c.d.ServicePassword {
		return nil
	}
	for _, u := range c.d.users {
		if u.DN == dn && u.Password == password {
			return nil
		}
	}
	return ldapclient.NewError(ldapclient.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
}

func (c *fakeDirectoryConnection) Close() error { return nil }

func (c *fakeDirectoryConnection) SearchWithPaging(r *ldapclient.SearchRequest, _ uint32) (*ldapclient.SearchResult, error) {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	result := &ldapclient.SearchResult{}
	if !strings.EqualFold(r.BaseDN, c.d.UserBaseDN) {
		return result, nil
	}
	for name, u := range c.d.users {
		if strings.Contains(r.Filter, "("+c.d.UsernameAttribute+"="+ldapclient.EscapeFilter(name)+")") {
			result.Entries = append(result.Entries, &ldapclient.Entry{
				DN:         u.DN,
				Attributes: []*ldapclient.EntryAttribute{{Name: c.d.UsernameAttribute, Values: []string{name}}},
			})
		}
	}
	return result, nil
}

func (c *fakeDirectoryConnection) SetTimeout(time.Duration) {}

func (c *fakeDirectoryConnection) StartTLS(*tls.Config) error { return nil }
