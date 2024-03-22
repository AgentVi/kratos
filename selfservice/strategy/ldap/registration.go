package ldap

import (
	"context"
	"encoding/json"
	"github.com/ory/kratos/driver/config"
	"net/http"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/x"
)

const (
	registrationFormPayloadSchema = `{
  "$id": "https://schemas.ory.sh/kratos/selfservice/ldap/registration/config.schema.json",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "traits": {}
  }
}`
)

var _ registration.Strategy = new(Strategy)

func (s *Strategy) RegisterRegistrationRoutes(_ *x.RouterPublic) {
}

func (s *Strategy) PopulateRegistrationMethod(r *http.Request, f *registration.Flow) error {
	return nil
}

func (s *Strategy) Register(w http.ResponseWriter, r *http.Request, f *registration.Flow, i *identity.Identity) (err error) {
	if err := r.ParseForm(); err != nil {
		s.d.Logger().WithRequest(r).WithError(err)
		return err
	}

	_, err = s.validateFlow(r.Context(), r, f.ID)
	if err != nil {
		return s.handleError(w, r, f, nil, err)
	}

	return nil
}

func (s *Strategy) extractIdentityTraits(ctx context.Context, user ldap.Entry, groups []*ldap.Entry) (rawjson string, err error) {
	conf, err := s.Config(ctx)
	if err != nil {
		return "", err
	}

	// TODO! This structure is strict matching on a specific setup of identityTraits.schema.json for ldap. Make this more generic solution so it fits many different schemas.
	type group struct {
		DN string `json:"dn"`
		Id string `json:"id"`
	}

	identityTraits := struct {
		Username string            `json:"username"`
		Metadata map[string]string `json:"metadata"`
		Groups   []group           `json:"groups"`
	}{
		Username: user.GetAttributeValue(conf.UserSearch.Username),
		Metadata: make(map[string]string),
		Groups:   []group{},
	}

	for _, list := range conf.UserSearch.IdentityAttributes {
		identityTraits.Metadata[list.Name] = user.GetAttributeValue(list.Attr)
	}

	for _, group_ := range groups {

		g := group{
			DN: group_.DN,
			Id: group_.GetAttributeValue(conf.GroupSearch.NameAttribute),
		}

		identityTraits.Groups = append(identityTraits.Groups, g)
	}

	rawid, err := json.Marshal(identityTraits)
	if err != nil {
		return "", err
	}

	return string(rawid), nil
}

func (s *Strategy) processRegistration(w http.ResponseWriter, r *http.Request, a *registration.Flow, user ldap.Entry, groups []*ldap.Entry) (*identity.Identity, error) {
	conf, err := s.Config(r.Context())
	if err != nil {
		s.d.Logger().WithError(err).Debug("LDAP Config")
		return nil, err
	}

	if _, _, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeLDAP, user.GetAttributeValue(conf.UserSearch.Username)); err == nil {
		return nil, nil
	}

	var schemaId = config.DefaultIdentityTraitsSchemaID
	if conf.SchemaId != "" {
		schemaId = conf.SchemaId
	}
	i := identity.NewIdentity(schemaId)
	traits, err := s.extractIdentityTraits(r.Context(), user, groups)
	if err != nil {
		return nil, err
	}
	i.Traits = identity.Traits(traits)

	creds, err := NewCredentials(user.GetAttributeValue(conf.UserSearch.Username))
	if err != nil {
		return nil, err
	}

	i.SetCredentials(s.ID(), *creds)
	if err := s.d.RegistrationExecutor().PostRegistrationHook(w, r, identity.CredentialsTypeLDAP, "", a, i); err != nil {
		s.d.Logger().WithRequest(r).WithError(err)

		return nil, err
	}

	return i, nil
}
