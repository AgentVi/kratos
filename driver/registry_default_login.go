// Copyright © 2023 Ory Corp
// Modifications Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"context"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/hook"
)

func (m *RegistryDefault) LoginHookExecutor() *login.HookExecutor {
	if m.selfserviceLoginExecutor == nil {
		m.selfserviceLoginExecutor = login.NewHookExecutor(m)
	}
	return m.selfserviceLoginExecutor
}

func (m *RegistryDefault) PreLoginHooks(ctx context.Context) (b []login.PreHookExecutor) {
	for _, v := range m.getHooks("", m.Config().SelfServiceFlowLoginBeforeHooks(ctx)) {
		if hook, ok := v.(login.PreHookExecutor); ok {
			b = append(b, hook)
		}
	}
	return
}

func (m *RegistryDefault) PostLoginHooks(ctx context.Context, credentialsType identity.CredentialsType) (b []login.PostHookExecutor) {
	for _, v := range m.getHooks(string(credentialsType), m.Config().SelfServiceFlowLoginAfterHooks(ctx, string(credentialsType))) {
		if hook, ok := v.(login.PostHookExecutor); ok {
			b = append(b, hook)
		}
	}

	if len(b) == 0 {
		// since we don't want merging hooks defined in a specific strategy and global hooks
		// global hooks are added only if no strategy specific hooks are defined
		for _, v := range m.getHooks(config.HookGlobal, m.Config().SelfServiceFlowLoginAfterHooks(ctx, "global")) {
			if hook, ok := v.(login.PostHookExecutor); ok {
				b = append(b, hook)
			}
		}
	}
	return
}

func (m *RegistryDefault) LoginEventNotifiers(ctx context.Context) (n []login.EventNotifier) {
	for _, h := range m.Config().SelfServiceFlowLoginNotificationHooks(ctx) {
		switch h.Name {
		case hook.KeyWebHook:
			n = append(n, hook.NewLoginEventWebHook(m, h.Config))
		default:
			m.Logger().
				WithField("hook", h.Name).
				Errorf("A unknown login notification hook was requested and can therefore not be used")
		}
	}
	return n
}

func (m *RegistryDefault) LoginHandler() *login.Handler {
	if m.selfserviceLoginHandler == nil {
		m.selfserviceLoginHandler = login.NewHandler(m)
	}

	return m.selfserviceLoginHandler
}

func (m *RegistryDefault) LoginFlowErrorHandler() *login.ErrorHandler {
	if m.selfserviceLoginRequestErrorHandler == nil {
		m.selfserviceLoginRequestErrorHandler = login.NewFlowErrorHandler(m)
	}

	return m.selfserviceLoginRequestErrorHandler
}
