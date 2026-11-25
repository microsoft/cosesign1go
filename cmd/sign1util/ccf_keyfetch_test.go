package main

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/Microsoft/cosesign1go/pkg/cosesign1"
)

func TestEncodeTTLPayloadDeterministic(t *testing.T) {
	publicKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	keys := []kidWithParsedKey{{Kid: "z", Key: publicKey}, {Kid: "a", Key: publicKey}}
	issuers := map[string][]kidWithParsedKey{"db": keys, "cp": keys, "a": keys}

	// Encoded issuer order is "a", "cp", "db"; key arrays retain their input order.
	keySetHex := "82a5010102417a03272006215820" + strings.Repeat("00", ed25519.PublicKeySize) +
		"a5010102416103272006215820" + strings.Repeat("00", ed25519.PublicKeySize)
	expected := mustHex(t, "a36161a101"+keySetHex+"626370a101"+keySetHex+"626462a101"+keySetHex)
	for i := 0; i < 100; i++ {
		actual, err := encodeTTLPayload(issuers)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, expected) {
			t.Fatalf("iteration %d: unexpected TTL CBOR:\ngot  %x\nwant %x", i, actual, expected)
		}
	}

	parsed, err := cosesign1.ParseTTLPayload(expected)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != len(issuers) {
		t.Fatalf("parsed %d issuers, want %d", len(parsed), len(issuers))
	}
	for issuer, keys := range issuers {
		if len(parsed[issuer]) != len(keys) {
			t.Fatalf("issuer %q: parsed %d keys, want %d", issuer, len(parsed[issuer]), len(keys))
		}
		for _, key := range keys {
			if !publicKey.Equal(parsed[issuer][key.Kid]) {
				t.Errorf("issuer %q: public key %q changed", issuer, key.Kid)
			}
		}
	}
}
