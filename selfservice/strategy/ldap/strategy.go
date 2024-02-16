package ldap

import (
	"context"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/gofrs/uuid"
	"github.com/ory/kratos/continuity"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
)

var _ login.Strategy = new(Strategy)
var _ registration.Strategy = new(Strategy)

type dependencies interface {
	config.Provider

	x.LoggingProvider
	x.WriterProvider

	x.CSRFTokenGeneratorProvider

	identity.PrivilegedPoolProvider

	session.HandlerProvider
	session.ManagementProvider

	login.HooksProvider
	login.ErrorHandlerProvider
	login.HookExecutorProvider
	login.FlowPersistenceProvider
	login.HandlerProvider

	registration.HookExecutorProvider
	registration.FlowPersistenceProvider
	registration.HooksProvider
	registration.StrategyProvider
	registration.HandlerProvider
	registration.ErrorHandlerProvider

	continuity.ManagementProvider
}

type Strategy struct {
	d         dependencies
	validator *validator.Validate
	dec       *decoderx.HTTP
}

func NewStrategy(d dependencies) *Strategy {
	return &Strategy{
		d:         d,
		validator: validator.New(),
		dec:       decoderx.NewHTTP(),
	}
}

func (s *Strategy) ID() identity.CredentialsType {
	return identity.CredentialsTypeLDAP
}

func (s *Strategy) handleError(w http.ResponseWriter, r *http.Request, f flow.Flow, traits []byte, err error) error {
	switch rf := f.(type) {
	case *login.Flow:
		return err
	case *registration.Flow:
		// Reset all nodes to not confuse users.
		// This is kinda hacky and will probably need to be updated at some point.

		rf.UI.Nodes = node.Nodes{}

		// Adds the "Continue" button
		rf.UI.SetCSRF(s.d.GenerateCSRFToken(r))

		if traits != nil {
			ds, err := s.d.Config().DefaultIdentityTraitsSchemaURL(r.Context())
			if err != nil {
				return err
			}

			traitNodes, err := container.NodesFromJSONSchema(r.Context(), node.LDAPGroup, ds.String(), "", nil)
			if err != nil {
				return err
			}

			rf.UI.Nodes = append(rf.UI.Nodes, traitNodes...)
			rf.UI.UpdateNodeValuesFromJSON(traits, "traits", node.LDAPGroup)
		}

		return err
	case *settings.Flow:
		return err
	}

	return err
}

func (s *Strategy) validateFlow(ctx context.Context, r *http.Request, rid uuid.UUID) (flow.Flow, error) {
	//if x.IsZeroUUID(rid) {
	//	return nil, errors.WithStack(herodot.ErrBadRequest.WithReason("The session cookie contains invalid values and the flow could not be executed. Please try again."))
	//}

	if ar, err := s.d.RegistrationFlowPersister().GetRegistrationFlow(ctx, rid); err == nil {
		if ar.Type != flow.TypeBrowser {
			return ar, ErrAPIFlowNotSupported
		}

		if err := ar.Valid(); err != nil {
			return ar, err
		}
		return ar, nil
	}

	ar, err := s.d.LoginFlowPersister().GetLoginFlow(ctx, rid)
	if err == nil {
		if ar.Type != flow.TypeBrowser {
			return ar, ErrAPIFlowNotSupported
		}

		if err := ar.Valid(); err != nil {
			return ar, err
		}
		return ar, nil
	}

	return ar, err // this must return the error
}

func (s *Strategy) NodeGroup() node.UiNodeGroup {
	return node.LDAPGroup
}

func (s *Strategy) CompletedAuthenticationMethod(ctx context.Context) session.AuthenticationMethod {
	return session.AuthenticationMethod{
		Method: s.ID(),
		AAL:    identity.AuthenticatorAssuranceLevel1,
	}
}
