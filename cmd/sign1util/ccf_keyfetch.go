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

	"github.com/Microsoft/cosesign1go/pkg/cosesign1"
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

// CertVerifier is invoked with the leaf certificate presented by a CCF node
// during TLS handshake. Returning nil accepts the certificate; returning an
// error aborts the connection.
type CertVerifier func(issuer string, cert *x509.Certificate) error

// fetchIssuerJWKS GETs https://<issuer>/jwks and returns the keys keyed by
// their `kid`. If verifyCert is not nil, the leaf certificate presented by the
// server is passed to verifyCert.
func fetchIssuerJWKS(issuer string, verifyCert CertVerifier) (map[string]crypto.PublicKey, error) {
	url := "https://" + issuer + "/jwks"
	tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // CCF uses self-signed certs that are supposed to be validated via attestation, and so will never pass the normal verification.
	if verifyCert != nil {
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
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", url, err)
	}
	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for i, k := range set.Keys {
		pub, err := jwkToPublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("key %d (kid=%s): %w", i, k.Kid, err)
		}
		if existingKey, exists := out[k.Kid]; exists {
			// Equal is implemented for all crypto.PublicKey types in std
			eq, ok := existingKey.(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !eq.Equal(pub) {
				return nil, fmt.Errorf("conflicting kid %s seen in JWKS from %s", k.Kid, url)
			}
			continue
		}
		out[k.Kid] = pub
	}
	return out, nil
}

// fetchCCFReceiptKeys returns a kid->PublicKey map by fetching the JWKS for
// each unique receipt issuer. If not nil, verifyCert is invoked with the leaf
// certificate presented by each issuer.
func fetchCCFReceiptKeys(receipts []cosesign1.ParsedCOSEReceipt, verifyCert CertVerifier) (map[string]crypto.PublicKey, error) {
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
		issuerKeys, err := fetchIssuerJWKS(r.Issuer, verifyCert)
		if err != nil {
			return nil, err
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
