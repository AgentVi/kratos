package ldap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ory/herodot"
	"github.com/ory/x/tlsx"
	pkgerrors "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateLDAPTestCertificate writes a self-signed certificate and key to a
// temporary directory and returns both the file paths and the base64 encoded
// PEM content.
//
// internal/testhelpers has GenerateTLSCertificateFilesForTests, but it cannot be
// used here: it imports driver, which imports this package, and these are
// internal tests.
func generateLDAPTestCertificate(t *testing.T) (certPath, keyPath, certBase64, keyBase64 string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certificate, err := tlsx.CreateSelfSignedCertificate(privateKey)
	require.NoError(t, err)

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})

	directory := t.TempDir()
	certPath = filepath.Join(directory, "cert.pem")
	keyPath = filepath.Join(directory, "key.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return certPath, keyPath,
		base64.StdEncoding.EncodeToString(certPEM),
		base64.StdEncoding.EncodeToString(keyPEM)
}

func TestResolveLDAPTLSMode_NoConfiguredMode_ShouldDeriveModeFromURLScheme(t *testing.T) {
	for ldapURL, expectedMode := range map[string]string{
		"ldaps://directory.example.test":     ldapTLSModeLDAPS,
		"ldaps://directory.example.test:636": ldapTLSModeLDAPS,
		"ldap://directory.example.test":      ldapTLSModePlaintext,
		"ldap://directory.example.test:389":  ldapTLSModePlaintext,
		"ldapi:///var/run/slapd/ldapi":       ldapTLSModePlaintext,
	} {
		t.Run(ldapURL, func(t *testing.T) {
			// Act
			mode, err := resolveLDAPTLSMode("", ldapURL)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, expectedMode, mode)
		})
	}
}

func TestResolveLDAPTLSMode_ModeContradictsURLScheme_ShouldReturnError(t *testing.T) {
	for _, testCase := range []struct {
		mode    string
		ldapURL string
	}{
		{mode: ldapTLSModeStartTLS, ldapURL: "ldaps://directory.example.test"},
		{mode: ldapTLSModeLDAPS, ldapURL: "ldap://directory.example.test"},
		{mode: ldapTLSModePlaintext, ldapURL: "ldaps://directory.example.test"},
	} {
		t.Run(testCase.mode+"/"+testCase.ldapURL, func(t *testing.T) {
			// Act
			_, err := resolveLDAPTLSMode(testCase.mode, testCase.ldapURL)

			// Assert
			require.Error(t, err)
			assert.Contains(t, err.Error(), testCase.mode)
		})
	}
}

func TestResolveLDAPTLSMode_UnsupportedMode_ShouldReturnError(t *testing.T) {
	// Act
	_, err := resolveLDAPTLSMode("tls", "ldaps://directory.example.test")

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported mode "tls"`)
}

func TestBuildLDAPTLSConfig_PlaintextMode_ShouldReturnNoTLSConfiguration(t *testing.T) {
	// Arrange
	configuration := &Configuration{URL: "ldap://directory.example.test"}

	// Act
	tlsConfiguration, err := buildLDAPTLSConfig(configuration, ldapTLSModePlaintext)

	// Assert
	require.NoError(t, err)
	assert.Nil(t, tlsConfiguration)
}

func TestBuildLDAPTLSConfig_NoTLSOptions_ShouldVerifyAgainstSystemRootsUsingURLHost(t *testing.T) {
	// Arrange
	configuration := &Configuration{URL: "ldaps://directory.example.test:636"}

	// Act
	tlsConfiguration, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, tlsConfiguration)
	assert.Equal(t, "directory.example.test", tlsConfiguration.ServerName)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfiguration.MinVersion)
	assert.False(t, tlsConfiguration.InsecureSkipVerify)
	assert.Nil(t, tlsConfiguration.RootCAs)
	assert.Empty(t, tlsConfiguration.Certificates)
}

func TestBuildLDAPTLSConfig_ConfiguredCACert_ShouldVerifyAgainstConfiguredRoots(t *testing.T) {
	// Arrange
	certPath, _, certBase64, _ := generateLDAPTestCertificate(t)
	certPEM, err := base64.StdEncoding.DecodeString(certBase64)
	require.NoError(t, err)
	expectedPool := x509.NewCertPool()
	require.True(t, expectedPool.AppendCertsFromPEM(certPEM))

	for name, caCert := range map[string]ldapPEMSource{
		"path":   {Path: certPath},
		"base64": {Base64: certBase64},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := &Configuration{URL: "ldaps://directory.example.test"}
			configuration.TLS.CACert = caCert

			// Act
			tlsConfiguration, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

			// Assert
			require.NoError(t, err)
			require.NotNil(t, tlsConfiguration.RootCAs)
			assert.True(t, tlsConfiguration.RootCAs.Equal(expectedPool))
		})
	}
}

func TestBuildLDAPTLSConfig_MalformedCACert_ShouldReturnError(t *testing.T) {
	// Arrange
	configuration := &Configuration{URL: "ldaps://directory.example.test"}
	configuration.TLS.CACert = ldapPEMSource{Base64: base64.StdEncoding.EncodeToString([]byte("not a certificate"))}

	// Act
	_, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_cert does not contain a PEM encoded certificate")
}

func TestBuildLDAPTLSConfig_UnreadableCACertPath_ShouldReturnError(t *testing.T) {
	// Arrange
	configuration := &Configuration{URL: "ldaps://directory.example.test"}
	configuration.TLS.CACert = ldapPEMSource{Path: filepath.Join(t.TempDir(), "missing.pem")}

	// Act
	_, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not read the PEM file")
}

func TestBuildLDAPTLSConfig_ConfiguredClientCertificate_ShouldAuthenticateWithClientCertificate(t *testing.T) {
	// Arrange
	certPath, keyPath, certBase64, keyBase64 := generateLDAPTestCertificate(t)

	for name, clientCertificate := range map[string]struct {
		cert ldapPEMSource
		key  ldapPEMSource
	}{
		"path":   {cert: ldapPEMSource{Path: certPath}, key: ldapPEMSource{Path: keyPath}},
		"base64": {cert: ldapPEMSource{Base64: certBase64}, key: ldapPEMSource{Base64: keyBase64}},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := &Configuration{URL: "ldaps://directory.example.test"}
			configuration.TLS.ClientCert = clientCertificate.cert
			configuration.TLS.ClientKey = clientCertificate.key

			// Act
			tlsConfiguration, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

			// Assert
			require.NoError(t, err)
			assert.Len(t, tlsConfiguration.Certificates, 1)
		})
	}
}

func TestBuildLDAPTLSConfig_ClientCertWithoutClientKey_ShouldReturnError(t *testing.T) {
	// Arrange
	certPath, _, _, _ := generateLDAPTestCertificate(t)
	configuration := &Configuration{URL: "ldaps://directory.example.test"}
	configuration.TLS.ClientCert = ldapPEMSource{Path: certPath}

	// Act
	_, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_cert and client_key must be configured together")
}

func TestBuildLDAPTLSConfig_MixedClientCertificateSources_ShouldReturnError(t *testing.T) {
	// Arrange
	certPath, _, _, keyBase64 := generateLDAPTestCertificate(t)
	configuration := &Configuration{URL: "ldaps://directory.example.test"}
	configuration.TLS.ClientCert = ldapPEMSource{Path: certPath}
	configuration.TLS.ClientKey = ldapPEMSource{Base64: keyBase64}

	// Act
	_, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must both be configured as either path or base64")
}

func TestBuildLDAPTLSConfig_ConfiguredServerName_ShouldOverrideURLHost(t *testing.T) {
	// Arrange
	configuration := &Configuration{URL: "ldaps://10.0.0.5:636"}
	configuration.TLS.ServerName = "directory.example.test"

	// Act
	tlsConfiguration, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "directory.example.test", tlsConfiguration.ServerName)
}

func TestBuildLDAPTLSConfig_ConfiguredMinVersion_ShouldLowerMinimumVersion(t *testing.T) {
	// Arrange
	configuration := &Configuration{URL: "ldaps://directory.example.test"}
	configuration.TLS.MinVersion = "1.0"

	// Act
	tlsConfiguration, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS10), tlsConfiguration.MinVersion)
}

func TestBuildLDAPTLSConfig_UnsupportedMinVersion_ShouldReturnError(t *testing.T) {
	// Arrange
	configuration := &Configuration{URL: "ldaps://directory.example.test"}
	configuration.TLS.MinVersion = "1.4"

	// Act
	_, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported min_version "1.4"`)
}

func TestBuildLDAPTLSConfig_InsecureSkipVerify_ShouldDisableCertificateVerification(t *testing.T) {
	// Arrange
	configuration := &Configuration{URL: "ldaps://directory.example.test"}
	configuration.TLS.InsecureSkipVerify = true

	// Act
	tlsConfiguration, err := buildLDAPTLSConfig(configuration, ldapTLSModeLDAPS)

	// Assert
	require.NoError(t, err)
	assert.True(t, tlsConfiguration.InsecureSkipVerify)
}

func TestLDAPTLSConfiguration_PathAndBase64Together_ShouldFailValidation(t *testing.T) {
	certPath, _, certBase64, _ := generateLDAPTestCertificate(t)

	for name, tlsConfiguration := range map[string]ldapTLSConfiguration{
		"ca_cert":     {CACert: ldapPEMSource{Path: certPath, Base64: certBase64}},
		"client_cert": {ClientCert: ldapPEMSource{Path: certPath, Base64: certBase64}},
		"client_key":  {ClientKey: ldapPEMSource{Path: certPath, Base64: certBase64}},
	} {
		t.Run(name, func(t *testing.T) {
			// Act
			err := tlsConfiguration.validate()

			// Assert
			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
			assert.Contains(t, err.Error(), "path and base64 cannot be configured together")
		})
	}
}

func TestLDAPConfig_StartTLSConfiguration_ShouldDecodeAndResolveTLS(t *testing.T) {
	// Arrange
	certPath, _, _, _ := generateLDAPTestCertificate(t)
	ldapConfig := newLDAPTestConfiguration()
	ldapConfig.TLS = ldapTLSConfiguration{
		Mode:       ldapTLSModeStartTLS,
		ServerName: "directory.example.test",
		CACert:     ldapPEMSource{Path: certPath},
	}
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig)

	// Act
	decodedConfiguration, err := strategy.Config(ctx)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, ldapTLSModeStartTLS, decodedConfiguration.resolvedTLSMode)
	require.NotNil(t, decodedConfiguration.resolvedTLSConfig)
	assert.Equal(t, "directory.example.test", decodedConfiguration.resolvedTLSConfig.ServerName)
	assert.NotNil(t, decodedConfiguration.resolvedTLSConfig.RootCAs)
}

func TestLDAPConfig_TLSModeContradictsURL_ShouldReturnConfigurationError(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	ldapConfig.URL = "ldaps://directory.example.test"
	ldapConfig.TLS.Mode = ldapTLSModeStartTLS
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig)

	// Act
	_, err := strategy.Config(ctx)

	// Assert
	require.Error(t, err)
	reason := pkgerrors.Cause(err).(*herodot.DefaultError).ReasonField
	assert.Contains(t, reason, "Invalid LDAP configuration")
	assert.Contains(t, reason, ldapTLSModeStartTLS)
}

func TestLDAPConfig_NoTLSConfiguration_ShouldRemainPlaintext(t *testing.T) {
	// Arrange
	ldapConfig := newLDAPTestConfiguration()
	ctx, strategy := newLDAPTestStrategy(t, ldapConfig)

	// Act
	decodedConfiguration, err := strategy.Config(ctx)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, ldapTLSModePlaintext, decodedConfiguration.resolvedTLSMode)
	assert.Nil(t, decodedConfiguration.resolvedTLSConfig)
}
