package ldap

import (
	_ "embed"
)

//go:embed .schema/login.schema.json
var loginSchema []byte
