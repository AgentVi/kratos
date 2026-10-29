// Copyright © 2024 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package ldap

import "github.com/ory/herodot"

var (
	ErrAPIFlowNotSupported = herodot.ErrBadRequest.WithError("API-based flows are not supported for this method").
		WithReasonf("LDAP is only supported for flows initiated using the Browser endpoint.")
)
