// Copyright © 2023 Ory Corp
// Modifications Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package embedx

import (
	"context"
	"embed"
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/jsonschema/v3"
)

func TestAddSchemaResources(t *testing.T) {
	for _, tc := range []struct {
		description       string
		dependencies      []SchemaType
		extraDependencies []SchemaType
		mustFail          bool
		failMessage       string
	}{
		{
			description:       "config schema",
			dependencies:      []SchemaType{Config},
			extraDependencies: nil,
		},
		{
			description:       "identity schema with dependencies",
			dependencies:      []SchemaType{IdentityMeta},
			extraDependencies: []SchemaType{IdentityExtension},
		},
		{
			description:       "multiple schemas",
			dependencies:      []SchemaType{Config, IdentityMeta, IdentityExtension},
			extraDependencies: nil,
		},
		{
			description:       "verify dependencies are also loaded",
			dependencies:      []SchemaType{IdentityMeta},
			extraDependencies: []SchemaType{IdentityExtension},
		},
		{
			description:  "must fail on unsupported schema types",
			dependencies: []SchemaType{4, 10},
			mustFail:     true,
			failMessage:  "the specified schema type (4) is not supported",
		},
	} {
		t.Run("case="+tc.description, func(t *testing.T) {
			c := jsonschema.NewCompiler()
			err := AddSchemaResources(c, tc.dependencies...)

			if tc.mustFail {
				assert.Errorf(t, err, "an error must be thrown on `%s`", tc.description)
				assert.EqualError(t, err, tc.failMessage)
			} else {
				assert.NoError(t, err)
			}

			if !tc.mustFail {
				for _, s := range append(tc.dependencies, tc.extraDependencies...) {
					_, err := c.Compile(context.Background(), s.GetSchemaID())
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestConfigSchema_LDAPSearchBaseConfiguration_ShouldRejectLegacyAndMultiBaseTogether(t *testing.T) {
	for _, searchConfiguration := range []string{"user_search", "group_search"} {
		t.Run(searchConfiguration, func(t *testing.T) {
			// Arrange
			compiler := jsonschema.NewCompiler()
			require.NoError(t, AddSchemaResources(compiler, Config))
			configSchema, err := compiler.Compile(context.Background(), Config.GetSchemaID())
			require.NoError(t, err)
			searchSettings := map[string]interface{}{
				"base_dns": []interface{}{
					map[string]interface{}{"base_dn": "ou=users,dc=example,dc=com"},
				},
			}
			configuration := map[string]interface{}{
				"dsn": "memory",
				"identity": map[string]interface{}{
					"schemas": []interface{}{
						map[string]interface{}{
							"id":  "default",
							"url": "file:///tmp/identity.schema.json",
						},
					},
				},
				"selfservice": map[string]interface{}{
					"default_browser_return_url": "https://example.com/",
					"methods": map[string]interface{}{
						"ldap": map[string]interface{}{
							"config": map[string]interface{}{
								searchConfiguration: searchSettings,
							},
						},
					},
				},
			}
			require.NoError(t, configSchema.ValidateInterface(configuration))
			searchSettings["base_dn"] = "ou=legacy,dc=example,dc=com"

			// Act
			err = configSchema.ValidateInterface(configuration)

			// Assert
			require.Error(t, err)
		})
	}
}

// newLDAPConfigurationForSchemaTest returns a minimal valid Kratos configuration
// with the given LDAP method configuration applied.
func newLDAPConfigurationForSchemaTest(ldapConfiguration map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"dsn": "memory",
		"identity": map[string]interface{}{
			"schemas": []interface{}{
				map[string]interface{}{
					"id":  "default",
					"url": "file:///tmp/identity.schema.json",
				},
			},
		},
		"selfservice": map[string]interface{}{
			"default_browser_return_url": "https://example.com/",
			"methods": map[string]interface{}{
				"ldap": map[string]interface{}{
					"config": ldapConfiguration,
				},
			},
		},
	}
}

func newConfigSchemaForTest(t *testing.T) *jsonschema.Schema {
	t.Helper()

	compiler := jsonschema.NewCompiler()
	require.NoError(t, AddSchemaResources(compiler, Config))
	configSchema, err := compiler.Compile(context.Background(), Config.GetSchemaID())
	require.NoError(t, err)

	return configSchema
}

func TestConfigSchema_LDAPTLSConfiguration_ShouldAcceptEveryOption(t *testing.T) {
	// Arrange
	configSchema := newConfigSchemaForTest(t)
	configuration := newLDAPConfigurationForSchemaTest(map[string]interface{}{
		"ldap_url": "ldaps://directory.example.com:636",
		"tls": map[string]interface{}{
			"mode":                 "ldaps",
			"server_name":          "directory.example.com",
			"insecure_skip_verify": false,
			"min_version":          "1.2",
			"ca_cert":              map[string]interface{}{"path": "/etc/ssl/certs/corp-ca.pem"},
			"client_cert":          map[string]interface{}{"path": "/etc/ldap/client.pem"},
			"client_key":           map[string]interface{}{"base64": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t"},
		},
	})

	// Act
	err := configSchema.ValidateInterface(configuration)

	// Assert
	require.NoError(t, err)
}

func TestConfigSchema_LDAPTLSConfiguration_ShouldRejectUnsupportedValues(t *testing.T) {
	for description, tlsConfiguration := range map[string]map[string]interface{}{
		"unsupported mode":        {"mode": "tls"},
		"unsupported min_version": {"min_version": "1.4"},
		"unknown tls property":    {"skip_verify": true},
		"unknown source property": {"ca_cert": map[string]interface{}{"file": "/etc/ssl/certs/corp-ca.pem"}},
		"non boolean skip verify": {"insecure_skip_verify": "yes"},
	} {
		t.Run("case="+description, func(t *testing.T) {
			// Arrange
			configSchema := newConfigSchemaForTest(t)
			configuration := newLDAPConfigurationForSchemaTest(map[string]interface{}{
				"tls": tlsConfiguration,
			})

			// Act
			err := configSchema.ValidateInterface(configuration)

			// Assert
			require.Error(t, err)
		})
	}
}

//go:embed testdata/identity_meta.*
var identityMetaTestCases embed.FS

func TestIdentityMetaSchema(t *testing.T) {
	c := jsonschema.NewCompiler()
	err := AddSchemaResources(c, IdentityMeta, IdentityExtension)
	require.NoError(t, err)

	schema, err := c.Compile(context.Background(), IdentityMeta.GetSchemaID())
	require.NoError(t, err)

	require.NoError(t, fs.WalkDir(identityMetaTestCases, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		t.Run("case="+path, func(t *testing.T) {
			f, err := identityMetaTestCases.Open(path)
			require.NoError(t, err)

			err = schema.Validate(f)
			if strings.HasSuffix(path, "invalid.schema.json") {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})

		return nil
	}))
}
