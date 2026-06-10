package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Microsoft/cosesign1go/pkg/cosesign1"
	"github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"
	"github.com/veraison/go-cose"
)

// jwk is a minimal JSON Web Key representation used to parse CCF transparency
// service /jwks responses.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

func jwkToPublicKey(k jwk) (crypto.PublicKey, error) {
	if k.Kty != "EC" {
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve %q", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decoding y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// DefaultAllowedJWKSDomains is the default allow list of domains from which
// JWKS will be fetched when validating CCF receipts. By default only Azure
// Confidential Ledger endpoints are permitted; additional domains can be
// allowed at the CLI level via --allow-jwks-domain.
var DefaultAllowedJWKSDomains = []string{"confidential-ledger.azure.com"}

// issuerHostRegex matches a plain DNS host of one or more dot-separated
// labels with an optional port. Issuers from receipt CWT claims must match
// this exactly; anything else (schemes, userinfo, paths, IP literals, etc.)
// is rejected to avoid SSRF when building the JWKS URL.
var issuerHostRegex = regexp.MustCompile(`^([a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(:\d+)?$`)

// validateIssuerForJWKSFetch verifies that issuer is a plain host[:port] and
// that its host is equal to or a subdomain of one of allowedDomains. The
// validated host (with optional port) is returned, suitable for use as the
// Host of an https URL.
func validateIssuerForJWKSFetch(issuer string, allowedDomains []string) (string, error) {
	if !issuerHostRegex.MatchString(issuer) {
		return "", fmt.Errorf("issuer %q is not a plain host[:port]", issuer)
	}
	host := issuer
	if i := strings.IndexByte(issuer, ':'); i >= 0 {
		host = issuer[:i]
	}
	hostLower := strings.ToLower(host)
	for _, d := range allowedDomains {
		dl := strings.ToLower(d)
		if hostLower == dl || strings.HasSuffix(hostLower, "."+dl) {
			return issuer, nil
		}
	}
	return "", fmt.Errorf("issuer host %q is not in the JWKS domain allow list (use --allow-jwks-domain to add)", host)
}

// CertVerifier is invoked with the leaf certificate presented by a CCF node
// during TLS handshake. Returning nil accepts the certificate; returning an
// error aborts the connection.
type CertVerifier func(issuer string, cert *x509.Certificate) error

type kidWithParsedKey struct {
	Kid string
	Key crypto.PublicKey
}

// fetchIssuerJWKS GETs https://<issuer>/jwks and returns the keys keyed by
// their `kid` as either a map or a list. If verifyCert is not nil, the leaf
// certificate presented by the server is passed to verifyCert. The issuer host
// is validated against allowedDomains before any network request is made.
func fetchIssuerJWKS(issuer string, allowedDomains []string, verifyCert CertVerifier) (outMap map[string]crypto.PublicKey, outList []kidWithParsedKey, err error) {
	host, err := validateIssuerForJWKSFetch(issuer, allowedDomains)
	if err != nil {
		return nil, nil, err
	}
	reqURL := (&url.URL{Scheme: "https", Host: host, Path: "/jwks"}).String()
	tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // CCF uses self-signed certs that are supposed to be validated via attestation, and so will never pass the normal verification.
	if verifyCert != nil {
		// VerifyPeerCertificate is called even if InsecureSkipVerify is true.
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server presented no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parsing server certificate: %w", err)
			}
			return verifyCert(issuer, cert)
		}
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(reqURL)
	if err != nil {
		return nil, nil, fmt.Errorf("GET %s: %w", reqURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("GET %s: status %d", reqURL, resp.StatusCode)
	}
	// Limit the response body to a sane size to avoid excessive memory usage
	// from a hostile or misconfigured server.
	const maxJWKSBytes = 1 << 20 // 1 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", reqURL, err)
	}
	if int64(len(body)) > maxJWKSBytes {
		return nil, nil, fmt.Errorf("reading %s: response exceeds %d bytes", reqURL, maxJWKSBytes)
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", reqURL, err)
	}
	outMap = make(map[string]crypto.PublicKey, len(set.Keys))
	outList = make([]kidWithParsedKey, 0, len(set.Keys))
	for i, k := range set.Keys {
		pub, err := jwkToPublicKey(k)
		if err != nil {
			return nil, nil, fmt.Errorf("key %d (kid=%s): %w", i, k.Kid, err)
		}
		if existingKey, exists := outMap[k.Kid]; exists {
			// Equal is implemented for all crypto.PublicKey types in std
			eq, ok := existingKey.(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !eq.Equal(pub) {
				return nil, nil, fmt.Errorf("conflicting kid %s seen in JWKS from %s", k.Kid, reqURL)
			}
			continue
		}
		outMap[k.Kid] = pub
		outList = append(outList, kidWithParsedKey{Kid: k.Kid, Key: pub})
	}
	return outMap, outList, nil
}

// Encodes a list of fetched keys into a COSE_KeySet.
func encodeKeySet(keys []kidWithParsedKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("empty keys list")
	}
	rawKeys := make([]cbor.RawMessage, 0, len(keys))
	for _, kidWithKey := range keys {
		kid := kidWithKey.Kid
		pk := kidWithKey.Key
		k, err := cose.NewKeyFromPublic(pk)
		if err != nil {
			return nil, errors.Wrapf(err, "construct cose.Key for key ID %q", kid)
		}
		k.ID = []byte(kid)
		raw, err := k.MarshalCBOR()
		if err != nil {
			return nil, errors.Wrapf(err, "MarshalCBOR for key ID %q", kid)
		}
		rawKeys = append(rawKeys, raw)
	}
	data, err := cbor.Marshal(rawKeys)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to encode the COSE_KeySet")
	}
	return data, nil
}

// encodeTTLPayload encodes a map from issuer to that issuer's fetched keys into
// an (unsigned) Transparency Trust List payload: a CBOR map from issuer strings
// to COSE_KeySet.
func encodeTTLPayload(issuerKeys map[string][]kidWithParsedKey) ([]byte, error) {
	if len(issuerKeys) == 0 {
		return nil, errors.New("empty TTL payload")
	}
	payload := make(map[string]cbor.RawMessage, len(issuerKeys))
	for issuer, keys := range issuerKeys {
		keySet, err := encodeKeySet(keys)
		if err != nil {
			return nil, errors.Wrapf(err, "encoding COSE_KeySet for issuer %q", issuer)
		}
		payload[issuer] = keySet
	}
	data, err := cbor.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to encode the TTL payload")
	}
	return data, nil
}

// fetchCCFReceiptKeys returns a kid->PublicKey map by fetching the JWKS for
// each unique receipt issuer. allowedDomains is the list of domains that
// receipt issuers must match (equal or subdomain) before any network request
// is made. If a receipt's issuer is present in preloaded, the supplied keys are
// used for that issuer instead of fetching its JWKS over the network. If not
// nil, verifyCert is invoked with the leaf certificate presented by each issuer.
func fetchCCFReceiptKeys(receipts []cosesign1.ParsedCOSEReceipt, allowedDomains []string, preloaded map[string]map[string]crypto.PublicKey, verifyCert CertVerifier) (map[string]crypto.PublicKey, error) {
	seen := map[string]bool{}
	keys := map[string]crypto.PublicKey{}
	for _, r := range receipts {
		if r.Issuer == "" {
			return nil, fmt.Errorf("receipt has no issuer; cannot fetch JWKS")
		}
		if seen[r.Issuer] {
			continue
		}
		seen[r.Issuer] = true
		var issuerKeys map[string]crypto.PublicKey
		if preloadedKeys, ok := preloaded[r.Issuer]; ok {
			issuerKeys = preloadedKeys
		} else {
			var err error
			issuerKeys, _, err = fetchIssuerJWKS(r.Issuer, allowedDomains, verifyCert)
			if err != nil {
				return nil, err
			}
		}
		for kid, k := range issuerKeys {
			if _, exists := keys[kid]; exists {
				return nil, fmt.Errorf("Issuer %s JWKS contains kid %s which is already present from another issuer", r.Issuer, kid)
			}
			keys[kid] = k
		}
	}
	return keys, nil
}
