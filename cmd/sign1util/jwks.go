package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
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

// publicKeyToJWK converts an EC public key into a jwk. kid is the COSE key ID
// (used verbatim as the JWK kid). Only EC keys are supported.
func publicKeyToJWK(kid string, pk crypto.PublicKey) (jwk, error) {
	ec, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return jwk{}, fmt.Errorf("unsupported key type %T (only EC keys are supported)", pk)
	}
	var crv string
	switch ec.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	default:
		return jwk{}, fmt.Errorf("unsupported curve %q", ec.Curve.Params().Name)
	}
	byteLen := (ec.Curve.Params().BitSize + 7) / 8
	return jwk{
		Kty: "EC",
		Kid: kid,
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(ec.X.FillBytes(make([]byte, byteLen))),
		Y:   base64.RawURLEncoding.EncodeToString(ec.Y.FillBytes(make([]byte, byteLen))),
	}, nil
}

// ttlToJWKSJSON renders a parsed TTL as prettified JSON of the form
// {"ledger-name": {"keys": [jwk, ...]}}. Keys within each ledger are sorted by
// kid for deterministic output.
func ttlToJWKSJSON(ttl map[string]map[string]crypto.PublicKey) ([]byte, error) {
	out := make(map[string]jwkSet, len(ttl))
	for issuer, keys := range ttl {
		jwks := make([]jwk, 0, len(keys))
		for kid, pk := range keys {
			j, err := publicKeyToJWK(kid, pk)
			if err != nil {
				return nil, fmt.Errorf("ledger %q: %w", issuer, err)
			}
			jwks = append(jwks, j)
		}
		sort.Slice(jwks, func(i, j int) bool { return jwks[i].Kid < jwks[j].Kid })
		out[issuer] = jwkSet{Keys: jwks}
	}
	return json.MarshalIndent(out, "", "  ")
}
