package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"os"

	"github.com/ory/x/tlsx"
	"github.com/pkg/errors"
)

const (
	// ldapTLSModeLDAPS is implicit TLS: the connection is encrypted before any
	// LDAP message is exchanged. This is the recommended mode.
	ldapTLSModeLDAPS = "ldaps"
	// ldapTLSModeStartTLS upgrades a plaintext connection using the StartTLS
	// extended operation (RFC 4511 section 4.14). A failed upgrade always fails
	// the connection, it never continues in plaintext.
	ldapTLSModeStartTLS = "starttls"
	// ldapTLSModePlaintext performs no encryption at all.
	ldapTLSModePlaintext = "insecure_plaintext"
)

const (
	ldapURLSchemeLDAP  = "ldap"
	ldapURLSchemeLDAPS = "ldaps"
)

// ldapPEMSource mirrors the tlsxSource definition in embedx/config.schema.json:
// PEM content is either read from a file or supplied inline as base64.
type ldapPEMSource struct {
	Path   string `json:"path"`
	Base64 string `json:"base64"`
}

type ldapTLSConfiguration struct {
	// Mode is one of ldaps, starttls or insecure_plaintext. When empty it is
	// derived from the scheme of the configured LDAP URL, which preserves the
	// behaviour of configurations written before this block existed.
	Mode string `json:"mode"`

	// ServerName overrides the hostname the server certificate is verified
	// against. When empty the host of the LDAP URL is used.
	ServerName string `json:"server_name"`

	InsecureSkipVerify bool `json:"insecure_skip_verify"`

	// MinVersion is one of 1.0, 1.1, 1.2 or 1.3 and defaults to 1.2. Lowering it
	// is only needed for legacy directory servers.
	MinVersion string `json:"min_version"`

	// CACert is the certificate authority used to verify the directory server.
	// When unset the system trust store is used.
	CACert ldapPEMSource `json:"ca_cert"`

	// ClientCert and ClientKey enable TLS client authentication and must be
	// configured together.
	ClientCert ldapPEMSource `json:"client_cert"`
	ClientKey  ldapPEMSource `json:"client_key"`
}

func (source ldapPEMSource) isZero() bool {
	return source.Path == "" && source.Base64 == ""
}

func (source ldapPEMSource) validate() error {
	if source.Path != "" && source.Base64 != "" {
		return errors.New("path and base64 cannot be configured together")
	}
	return nil
}

func (source ldapPEMSource) read() ([]byte, error) {
	switch {
	case source.Base64 != "":
		pemBytes, err := base64.StdEncoding.DecodeString(source.Base64)
		if err != nil {
			return nil, errors.Wrap(err, "could not base64 decode the configured PEM content")
		}
		return pemBytes, nil
	case source.Path != "":
		pemBytes, err := os.ReadFile(source.Path)
		if err != nil {
			return nil, errors.Wrapf(err, "could not read the PEM file %q", source.Path)
		}
		return pemBytes, nil
	default:
		return nil, errors.New("neither path nor base64 is configured")
	}
}

func (configuration *ldapTLSConfiguration) validate() error {
	for name, source := range map[string]ldapPEMSource{
		"ca_cert":     configuration.CACert,
		"client_cert": configuration.ClientCert,
		"client_key":  configuration.ClientKey,
	} {
		if err := source.validate(); err != nil {
			return errors.Wrap(err, name)
		}
	}

	return nil
}

// ldapURLScheme returns the scheme of the configured LDAP URL. net/url
// lowercases the scheme, so the result is always comparable to the constants
// above.
func ldapURLScheme(ldapURL string) (string, error) {
	parsedURL, err := url.Parse(ldapURL)
	if err != nil {
		return "", errors.Wrapf(err, "could not parse ldap_url %q", ldapURL)
	}
	return parsedURL.Scheme, nil
}

func ldapURLHostname(ldapURL string) (string, error) {
	parsedURL, err := url.Parse(ldapURL)
	if err != nil {
		return "", errors.Wrapf(err, "could not parse ldap_url %q", ldapURL)
	}
	return parsedURL.Hostname(), nil
}

// resolveLDAPTLSMode determines the effective TLS mode and rejects modes that
// contradict the URL scheme. StartTLS on an ldaps:// URL would otherwise fail at
// runtime with "already encrypted", and ldaps on an ldap:// URL would silently
// connect in plaintext.
func resolveLDAPTLSMode(configuredMode string, ldapURL string) (string, error) {
	scheme, err := ldapURLScheme(ldapURL)
	if err != nil {
		return "", err
	}

	switch configuredMode {
	case "":
		if scheme == ldapURLSchemeLDAPS {
			return ldapTLSModeLDAPS, nil
		}
		return ldapTLSModePlaintext, nil
	case ldapTLSModeLDAPS:
		if scheme != ldapURLSchemeLDAPS {
			return "", errors.Errorf("mode %q requires an %s:// ldap_url", ldapTLSModeLDAPS, ldapURLSchemeLDAPS)
		}
		return ldapTLSModeLDAPS, nil
	case ldapTLSModeStartTLS:
		if scheme != ldapURLSchemeLDAP {
			return "", errors.Errorf("mode %q requires an %s:// ldap_url", ldapTLSModeStartTLS, ldapURLSchemeLDAP)
		}
		return ldapTLSModeStartTLS, nil
	case ldapTLSModePlaintext:
		if scheme == ldapURLSchemeLDAPS {
			return "", errors.Errorf("mode %q cannot be used with an %s:// ldap_url", ldapTLSModePlaintext, ldapURLSchemeLDAPS)
		}
		return ldapTLSModePlaintext, nil
	default:
		return "", errors.Errorf("unsupported mode %q", configuredMode)
	}
}

func resolveLDAPTLSMinVersion(configuredVersion string) (uint16, error) {
	switch configuredVersion {
	case "":
		return tls.VersionTLS12, nil
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, errors.Errorf("unsupported min_version %q", configuredVersion)
	}
}

// buildLDAPTLSConfig returns the TLS configuration used for both the implicit
// TLS dial and the StartTLS upgrade, or nil when the mode is plaintext.
func buildLDAPTLSConfig(configuration *Configuration, mode string) (*tls.Config, error) {
	if mode == ldapTLSModePlaintext {
		return nil, nil
	}

	minVersion, err := resolveLDAPTLSMinVersion(configuration.TLS.MinVersion)
	if err != nil {
		return nil, err
	}

	// go-ldap's StartTLS hands this configuration straight to tls.Client, which
	// does not infer a hostname the way tls.Dial does, so ServerName has to be
	// set explicitly for verification to work at all.
	serverName := configuration.TLS.ServerName
	if serverName == "" {
		if serverName, err = ldapURLHostname(configuration.URL); err != nil {
			return nil, err
		}
	}

	tlsConfiguration := &tls.Config{
		MinVersion:         minVersion,
		ServerName:         serverName,
		InsecureSkipVerify: configuration.TLS.InsecureSkipVerify,
	}

	if !configuration.TLS.CACert.isZero() {
		caPEM, err := configuration.TLS.CACert.read()
		if err != nil {
			return nil, errors.Wrap(err, "ca_cert")
		}

		certificatePool := x509.NewCertPool()
		if !certificatePool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("ca_cert does not contain a PEM encoded certificate")
		}
		tlsConfiguration.RootCAs = certificatePool
	}

	clientCertificate, err := loadLDAPClientCertificate(configuration.TLS)
	if err != nil {
		return nil, err
	}
	if clientCertificate != nil {
		tlsConfiguration.Certificates = []tls.Certificate{*clientCertificate}
	}

	return tlsConfiguration, nil
}

func loadLDAPClientCertificate(configuration ldapTLSConfiguration) (*tls.Certificate, error) {
	if configuration.ClientCert.isZero() && configuration.ClientKey.isZero() {
		return nil, nil
	}
	if configuration.ClientCert.isZero() || configuration.ClientKey.isZero() {
		return nil, errors.New("client_cert and client_key must be configured together")
	}

	// Both halves have to use the same form. Mixing them is rejected below
	// rather than silently loading half a key pair.
	if configuration.ClientCert.Base64 != "" && configuration.ClientKey.Base64 != "" {
		certificate, err := tlsx.CertificateFromBase64(configuration.ClientCert.Base64, configuration.ClientKey.Base64)
		if err != nil {
			return nil, errors.Wrap(err, "could not load the LDAP client certificate")
		}
		return &certificate, nil
	}

	if configuration.ClientCert.Path != "" && configuration.ClientKey.Path != "" {
		certificate, err := tls.LoadX509KeyPair(configuration.ClientCert.Path, configuration.ClientKey.Path)
		if err != nil {
			return nil, errors.Wrap(err, "could not load the LDAP client certificate")
		}
		return &certificate, nil
	}

	return nil, errors.New("client_cert and client_key must both be configured as either path or base64")
}
