package ldap

import (
	"github.com/gofrs/uuid"
	"github.com/ory/herodot"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/sqlcon"
	"github.com/pkg/errors"
	"net/http"
	"time"
)

func (s *Strategy) RegisterLoginRoutes(r *x.RouterPublic) {
}

func (s *Strategy) handleLoginError(w http.ResponseWriter, r *http.Request, f *login.Flow, payload *submitSelfServiceLoginFlowWithLDAPMethodBody, err error) error {
	if f != nil {
		f.UI.Nodes.ResetNodes("password")
		f.UI.Nodes.SetValueAttribute("identifier", payload.Identifier)
		if f.Type == flow.TypeBrowser {
			f.UI.SetCSRF(s.d.GenerateCSRFToken(r))
		}
	}

	return err
}

func (s *Strategy) Login(w http.ResponseWriter, r *http.Request, f *login.Flow, identityID uuid.UUID) (i *identity.Identity, err error) {
	if err := login.CheckAAL(f, identity.AuthenticatorAssuranceLevel1); err != nil {
		return nil, err
	}

	if err := flow.MethodEnabledAndAllowedFromRequest(r, s.ID().String(), s.d); err != nil {
		return nil, err
	}

	var p submitSelfServiceLoginFlowWithLDAPMethodBody
	if err := s.dec.Decode(r, &p,
		decoderx.HTTPDecoderSetValidatePayloads(true),
		decoderx.MustHTTPRawJSONSchemaCompiler(loginSchema),
		decoderx.HTTPDecoderJSONFollowsFormFormat()); err != nil {
		return nil, s.handleLoginError(w, r, f, &p, err)
	}

	if err := flow.EnsureCSRF(s.d, r, f.Type, s.d.Config().DisableAPIFlowEnforcement(r.Context()), s.d.GenerateCSRFToken, p.CSRFToken); err != nil {
		return nil, s.handleLoginError(w, r, f, &p, err)
	}

	user, groups, err := s.ldapLogin(r.Context(), p.Identifier, p.Password)
	if err != nil {
		s.d.Logger().WithError(err).Error()
		return nil, s.handleLoginError(w, r, f, &p, errors.WithStack(schema.NewInvalidCredentialsError()))
	}

	conf, err := s.Config(r.Context())
	if err != nil {
		s.d.Logger().WithError(err).Error("LDAP configuration faulted")
		return nil, err
	}

	userId := user.GetAttributeValue(conf.UserSearch.Username)

	i, _, err = s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), s.ID(), userId)
	if err != nil && errors.Is(err, sqlcon.ErrNoRows) {
		// Create new identity in memory, to be able to add the identify if the authorization succeed after login webhook
		// INFORMATION about the flow
		// This require webhook and the receiver handle the creation of the identity and send it back as a response
		// --HAPPY FLOW--
		// KRATOS
		// (Login -> Challenge Authentication using LDAP -> Create temp identity -> Send identity information using LDAP after login webhook) -->
		// WEBHOOK RECEIVER
		// --> (Challenge authorize and add Identity on receiver end -> Return Identity in webhook response) -->
		// KRATOS
		// --> (Create Session and Cookie -> Login Success)
		//
		// -- FAIL FLOW --
		// WEBHOOK RECEIVER
		// --> (If challenge authorize fail -> Remove Identity if exist on receiver end -> Response with 403 and errormessage) -->
		// KRATOS
		// --> (Login failed)

		// TODO! Its also possible to start Registration flow to register a new identity if the authentication success, shall we add that possibility and it to the ldap flow config?
		i = identity.NewIdentity(identity.CredentialsTypeLDAP.String())
	} else if conf.UpdateUserIdentity.Enabled &&
		time.Now().After(i.UpdatedAt.Add(conf.UpdateUserIdentity.RefreshTime.Duration)) {
		traits, err := s.extractIdentityTraits(r.Context(), user, groups)
		if err != nil {
			return nil, herodot.ErrInternalServerError.WithReason("The password credentials could not be decoded properly").WithDebug(err.Error()).WithWrap(err)
		}
		i.Traits = identity.Traits(traits)

		err = s.d.PrivilegedIdentityPool().UpdateIdentity(r.Context(), i)
		if err != nil {
			return nil, err
		}
	}

	if !conf.UpdateUserIdentity.Enabled || i.ID == uuid.Nil {
		// Update traits on every login
		traits, err := s.extractIdentityTraits(r.Context(), user, groups)
		if err != nil {
			return nil, err
		}
		i.Traits = identity.Traits(traits)
	}

	f.Active = s.ID()
	if err = s.d.LoginFlowPersister().UpdateLoginFlow(r.Context(), f); err != nil {
		return nil, s.handleLoginError(w, r, f, &p, errors.WithStack(herodot.ErrInternalServerError.WithReason("Could not update flow").WithDebug(err.Error())))
	}

	return i, nil
}

func (s *Strategy) PopulateLoginMethod(r *http.Request, requestedAAL identity.AuthenticatorAssuranceLevel, sr *login.Flow) error {
	// This strategy can only solve AAL1
	if requestedAAL > identity.AuthenticatorAssuranceLevel1 {
		return nil
	}

	sr.UI.SetCSRF(s.d.GenerateCSRFToken(r))
	sr.UI.SetNode(node.NewInputField("ldap_identifier", "", node.LDAPGroup, node.InputAttributeTypeText, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoNodeLabelID()))
	sr.UI.SetNode(NewLDAPNode("ldap_password", node.InputAttributeAutocompleteCurrentPassword))
	sr.UI.GetNodes().Append(node.NewInputField("method", "ldap", node.LDAPGroup, node.InputAttributeTypeSubmit).WithMetaLabel(text.NewInfoLogin()))

	return nil
}
