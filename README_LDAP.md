# LDAP Integration

This document describes how the `ldap` self-service strategy in
`selfservice/strategy/ldap/` authenticates users against a directory server
(OpenLDAP, Active Directory, or any LDAPv3-compatible server) and turns
directory entries into Kratos identities.

## Where the code lives

```
selfservice/strategy/ldap/
  strategy.go     Strategy struct, dependency wiring, NodeGroup/ID
  config.go       Configuration struct, JSON decoding, validation, search-base resolution
  ldap.go         Directory access: connections, searches, filters, login + group resolution
  login.go        Login HTTP handler, identity lookup/creation, error mapping
  registration.go Registration handler stub + identity trait extraction
  nodes.go        UI node for the password input field
  schema.go       Embeds the login payload JSON schema
  error.go        Static strategy-level errors
  types.go        Login request payload, LDAP credentials config, FlowMethod
  .schema/login.schema.json  JSON schema validating the login form payload
```

The strategy is registered in `driver/registry_default.go` alongside the
other login/registration strategies (`ldap.NewStrategy(m)`), and it
implements both `login.Strategy` and `registration.Strategy`. Its
`ID()` is `identity.CredentialsTypeLDAP` ("ldap"), and its config lives under
`selfservice.methods.ldap` in `kratos.yml`, validated against
`embedx/config.schema.json`.

## Configuration

```yaml
selfservice:
  methods:
    ldap:
      enabled: true
      config:
        ldap_url: ldap://127.0.0.1:1389
        bind_dn: cn=admin,dc=example,dc=org
        bind_pw: adminpassword

        user_search:
          base_dn: ou=users,dc=example,dc=org      # legacy single base
          # base_dns:                               # OR a list of bases (mutually exclusive with base_dn)
          #   - base_dn: ou=employees,dc=example,dc=org
          #     scope: whole_subtree                # base_object | single_level | whole_subtree
          #   - base_dn: ou=contractors,dc=example,dc=org
          #     scope: single_level
          filter: (objectClass=inetOrgPerson)
          username: uid
          identity_attributes:
            - name: firstname
              attr: givenName
            - name: email
              attr: mail

        group_search:
          base_dn: ou=groups,dc=example,dc=org       # or base_dns, same rules as above
          filter: (objectClass=organizationalUnit)
          name_attr: cn
          groups_from_user_memberof: false
          user_matchers:
            - user_attr: uid
              group_attr: uniqueMember

        update_user_identity:
          enabled: true
          refresh_time: 5m
```

`Strategy.Config(ctx)` (`config.go`) decodes this JSON with a strict decoder
(unknown fields are rejected) and then runs `validate()`, which:

- resolves `user_search`/`group_search` base configuration (see below) and
  rejects `base_dn` + `base_dns` being set together,
- compiles `user_search.filter` and `group_search.filter` as LDAP filters if
  set, rejecting syntactically invalid ones,
- requires at least one `group_search.user_matchers` entry when
  `groups_from_user_memberof` is `false`.

Any validation failure surfaces as `herodot.ErrInternalServerError` ("Invalid
LDAP configuration"). The same mutual-exclusivity rule for `base_dn`/`base_dns`
is also enforced directly in `embedx/config.schema.json` via a `not: {required: [...]}`
constraint on both `user_search` and `group_search`, so a bad config is
rejected at config-load time, not just on first login.

### Single base vs. multiple search bases

`resolveLDAPSearchBases` (`config.go`) turns the configured `base_dn`
(a single string, whole-subtree scope, kept for backward compatibility) or
`base_dns` (a list of `{base_dn, scope}` objects) into a list of
`resolvedLDAPSearchBase{distinguishedName, searchScope}`. This lets a single
`user_search`/`group_search` block search across several disjoint branches of
the directory tree (e.g. users under both `ou=employees` and
`ou=contractors`) instead of assuming one flat OU. Every search function
(`ldapUserEntry`, `ldapGroupsUserMatchers`) iterates all resolved bases and
merges results.

## Login flow (`ldap.go` + `login.go`)

`Strategy.Login` is invoked by the login flow handler once the user submits
the LDAP method form (`ldap_identifier` + `ldap_password`, validated against
`.schema/login.schema.json`). It calls `s.ldapLogin(ctx, identifier, password)`,
which does the following, all using **one LDAP connection** dialed once with
`openLDAPConnection` (dial timeout 9s, request/read timeout 8s via
`SetTimeout`):

1. **Bind as the service account** using `bind_dn`/`bind_pw`. Failure here is
   an operational error (misconfiguration or directory outage), not a bad
   end-user password.
2. **Find the user** (`ldapUserEntry`): builds the filter
   `(&(username=<escaped identifier>)<user_search.filter>)` via
   `combineLDAPFilters`, then runs a paged search (`SearchWithPaging`, page
   size 500, `NeverDerefAliases`, 8s server-side time limit) against every
   resolved `user_search` base. Zero matches across all bases →
   `errLDAPUserNotFound`. More than one match (including across different
   bases) → `errLDAPMultipleUsersFound`, so a directory that is misconfigured
   to contain duplicate usernames fails closed instead of picking one
   arbitrarily.
3. **Verify the password** (`verifyLDAPPassword`): opens a *second*, throwaway
   connection and attempts `Bind(user.DN, password)` on it. A separate
   connection is used deliberately so the service connection (still bound as
   the service account) can go on to do the group search; reusing it would
   downgrade its bind to the end user's credentials or require re-binding.
   An `LDAPResultInvalidCredentials` error is treated as a normal
   authentication failure; any other bind error is an operational error.
4. **Resolve group membership** (`ldapGroupEntries`) on the original service
   connection — see below.
5. Return the user entry and its groups to `login.go`.

`login.go` then:

- maps directory/operational failures to `schema.NewLDAPStatusServiceUnavailable()`,
  and user-not-found / multiple-users / bad-password to
  `schema.NewInvalidCredentialsError()` (`ldapLoginError`) — directory errors
  are actionable for an operator, but the three "the login didn't match"
  cases are intentionally indistinguishable from each other so no
  information about which usernames exist leaks to a caller,
- looks up an existing Kratos identity by the LDAP `username` attribute value
  via `FindByCredentialsIdentifier`,
- if none exists, creates a new in-memory identity
  (`identity.NewIdentity(identity.CredentialsTypeLDAP.String())`) — actual
  persistence is expected to happen through an `after` login webhook (see the
  flow diagram comment in `login.go`); this is a deliberate, still-evolving
  integration point, not a bug,
- if `update_user_identity.enabled` is true and the stored identity is older
  than `refresh_time`, or if update-on-login is disabled entirely, re-derives
  the identity's `traits` from the current directory data
  (`extractIdentityTraits`, see below) and persists the update.

## Group resolution: two modes

`ldapGroupEntries` picks one of two strategies based on
`group_search.groups_from_user_memberof`:

### 1. `user_matchers` (default, `ldapGroupsUserMatchers`)

For each configured `{user_attr, group_attr}` pair, builds a match clause:

- if `group_attr` is `member` or `uniqueMember`, matches the group's member
  attribute against the **user's DN** (`(uniqueMember=<user DN>)`) — the
  common "group lists its members by full DN" pattern,
- otherwise matches the group attribute against the corresponding user
  attribute's value (`(memberUid=<user's uid>)`) — the "group lists members
  by short identifier" pattern used by e.g. `posixGroup`. If the user entry
  is missing that attribute, this is a hard error rather than a silently
  empty filter clause.

All matcher clauses plus `group_search.filter` are AND-ed together
(`ldapGroupSearchFilter` + `combineLDAPFilters`), and the resulting filter is
searched across every resolved `group_search` base. Results from all bases
are merged and de-duplicated by DN (case-insensitively).

### 2. `groups_from_user_memberof` (`ldapGroupsFromUserMemberOf`)

Reads the user's `memberOf` attribute values (queried as part of the user
search — see `ldapUserSearchAttributes`), de-duplicates them
case-insensitively, and for each unique group DN issues a **base-object
search** (`scope=base`) using that DN directly as the search base with filter
`group_search.filter` (or `(objectClass=*)` if unset). This is deliberately
portable: it works identically on OpenLDAP and Active Directory, and it
resolves a group regardless of where it lives in the tree — it does **not**
require the group to be under the configured `group_search.base_dn`/`base_dns`
(those settings are unused in this mode; only `group_search.filter` and
`group_search.name_attr` apply). A `memberOf` DN that no longer exists is
silently skipped; more than one entry for the same DN (which should be
impossible in a correctly behaving directory) is treated as an error.

Only **direct** `memberOf` values are expanded — Active Directory's nested
group membership and a user's primary group (via `primaryGroupID`) are
intentionally not resolved. This is documented as deliberate, deferred
follow-up work (see `PLANS.md` and the field comment on
`GroupSearch.GroupsFromUserMemberOf`).

Regardless of mode, only the DN and `group_search.name_attr` value are
fetched per group (`ldapGroupSearchAttributes`) — the full entry isn't
needed downstream.

## Turning directory data into identity traits

`extractIdentityTraits` (`registration.go`) builds a fixed JSON shape:

```json
{
  "loginId": "<user_search.username attribute value>",
  "metadata": { "<identity_attributes[].name>": "<...attr value>", ... },
  "groups": [ { "dn": "<group DN>", "id": "<group_search.name_attr value>" }, ... ]
}
```

This is intentionally coupled to a specific identity schema shape (see
`contrib/quickstart/kratos/ldap/identity.schema.json`, which declares
`traits.loginId` as the LDAP credentials identifier, plus `traits.metadata`
and `traits.groups`). The code has a `TODO` acknowledging this is not yet
generic across arbitrary identity schemas.

## Error handling model

- `ldapOperationalError` (`ldap.go`) wraps any error that reflects a
  directory/connection/search failure as opposed to a credentials problem.
  `isLDAPOperationalError` unwraps via `errors.As` to detect it anywhere in
  an error chain. These map to a 503-style "service unavailable" response.
- `errLDAPUserNotFound` and `errLDAPMultipleUsersFound` are sentinel errors
  (`errors.New`, matched with `errors.Is`) that both map to the generic
  "invalid credentials" response, alongside an actual LDAP invalid-password
  bind result — so an attacker cannot distinguish "wrong password" from
  "no such user" from "directory has duplicate accounts for this username".

## Connections, paging, and timeouts

- `ldapDialer` is an injectable function (`Strategy.ldapDial`, defaulting to
  `defaultLDAPDialer`) so tests can substitute a fake `ldapConnection`
  without a live directory.
- `openLDAPConnection` dials with a 9s TCP dial timeout and then sets an 8s
  read/write timeout (`ldapRequestTimeout`) on the connection.
- All searches go through `ldapSearch`, which always uses
  `SearchWithPaging` with a 500-entry page size (`ldapPageSize`) so large
  result sets (e.g. a group search over a big tree) don't require the
  directory to buffer everything in one response.
- Every `SearchRequest` (`newLDAPSearchRequest`) sets an 8-second server-side
  time limit (`ldapSearchTimeLimitSeconds`) and `NeverDerefAliases`.
- Within a single login, the user search and group search share one bound
  connection; only password verification uses a second, separate connection
  (see above). Connections are always closed via `closeLDAPConnection`,
  which logs (but does not fail the request on) close errors.

## Testing

`ldap_test.go` exercises this package against a mock `ldapConnection`
(`ldapConnectionMock`) rather than a real directory, covering: filter
construction for both group-resolution modes, multi-base search and
de-duplication, paging/partial-result handling, timeout/dial-failure wiring,
duplicate-user and duplicate-`memberOf`-DN handling, config decoding of
`base_dns`, and the `Config → validate → resolveLDAPSearchBases` chain.
`embedx/embedx_test.go` additionally verifies that the JSON schema itself
rejects `base_dn` and `base_dns` being configured together for both
`user_search` and `group_search`.

Run just this package's tests with:

```sh
go test ./selfservice/strategy/ldap/... ./embedx/...
```

## Trying it out

`contrib/quickstart/kratos/ldap/` contains a ready-to-use `kratos.yml` (LDAP
method enabled, pointed at a local OpenLDAP on `ldap://127.0.0.1:1389`) and a
matching `identity.schema.json`. It uses `user_matchers` with `uniqueMember`
against `ou=groups,dc=example,dc=org`; the commented-out `base_dns` blocks in
that file show how to opt into multi-branch search bases instead of the
single `base_dn`.

## Known limitations (deliberate, not bugs)

- `groups_from_user_memberof` only expands direct group membership; AD
  nested groups and primary-group membership are not resolved.
- `registration.go`'s `Register`/`processRegistration` handlers exist but the
  active identity-creation path today is the "not found → create in-memory
  identity" branch inside `login.go`'s `Login`, intended to be completed by
  an `after` login webhook.
- `Strategy.Config` re-decodes and re-validates the configuration (including
  recompiling both LDAP filters) on every call, and it is called more than
  once per login request. This is a minor efficiency cost on the
  authentication hot path, not a correctness issue.
