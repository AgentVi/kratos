// Copyright © 2024 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	_ "embed"
)

//go:embed .schema/login.schema.json
var loginSchema []byte
