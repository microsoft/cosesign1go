//go:build linux
// +build linux

package cosesign1

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"testing"

	"github.com/veraison/go-cose"
)

func readFileBytes(filename string) ([]byte, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		println("Error reading '" + filename + "': " + string(err.Error()))
		return nil, err
	}
	if len(content) == 0 {
		println("Warning: empty file '" + filename + "'")
	}
	return content, nil
}

func readFileBytesOrExit(filename string) []byte {
	val, err := readFileBytes(filename)
	if err != nil {
		println("failed to load from file '" + filename + "' with error " + string(err.Error()))
		os.Exit(1)
	}
	return val
}

func readFileStringOrExit(filename string) string {
	val := readFileBytesOrExit(filename)
	return string(val)
}

var fragmentRego string
var fragmentCose []byte
var leafPrivatePem string
var leafCertPEM string
var leafPubkeyPEM string
var certChainPEM string

func TestMain(m *testing.M) {
	fmt.Println("Generating files...")
	makeCleanOut, err := exec.Command("make", "clean").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to clean up: %s\n", err)
		fmt.Fprintf(os.Stderr, string(makeCleanOut))
		os.Exit(1)
	}

	outputBytes, err := exec.Command("make", "chain.pem", "infra.rego.cose", "leaf.private.pem").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build the required test files: %s", err)
		fmt.Fprintf(os.Stderr, string(outputBytes))
		os.Exit(1)
	}
	fmt.Println(string(outputBytes))

	fragmentRego = readFileStringOrExit("infra.rego")
	fragmentCose = readFileBytesOrExit("infra.rego.cose")
	leafPrivatePem = readFileStringOrExit("leaf.private.pem")
	leafCertPEM = readFileStringOrExit("leaf.cert.pem")
	leafPubkeyPEM = readFileStringOrExit("leaf.public.pem")
	certChainPEM = readFileStringOrExit("chain.pem")

	os.Exit(m.Run())
}

func comparePEMs(pk1pem string, pk2pem string) bool {
	pk1der := pem2der([]byte(pk1pem))
	pk2der := pem2der([]byte(pk2pem))
	return bytes.Equal(pk1der, pk2der)
}

func base64PublicKeyToPEM(base64Key string) string {
	begin := "-----BEGIN PUBLIC KEY-----\n"
	end := "\n-----END PUBLIC KEY-----"

	pemData := begin + base64Key + end
	return pemData
}

// Decode a COSE_Sign1 document and check that we get the expected payload, issuer, keys, certs etc.
func Test_UnpackAndValidateCannedFragment(t *testing.T) {
	var unpacked *UnpackedCoseSign1
	unpacked, err := UnpackAndValidateCOSE1CertChain(fragmentCose)

	if err != nil {
		t.Fatalf("UnpackAndValidateCOSE1CertChain failed: %s", err)
	}

	iss := unpacked.Issuer
	feed := unpacked.Feed
	pubkey := base64PublicKeyToPEM(unpacked.Pubkey)
	pubcert := base64CertToPEM(unpacked.Pubcert)
	payload := string(unpacked.Payload[:])
	cty := unpacked.ContentType

	if !comparePEMs(pubkey, leafPubkeyPEM) {
		t.Fatal("pubkey did not match")
	}
	if !comparePEMs(pubcert, leafCertPEM) {
		t.Fatal("pubcert did not match")
	}
	if cty != "application/unknown+rego" {
		t.Fatalf("cty did not match: %s", cty)
	}
	if payload != fragmentRego {
		t.Fatal("payload did not match")
	}
	if iss != "TestIssuer" {
		t.Fatalf("iss did not match: %s", iss)
	}
	if feed != "TestFeed" {
		t.Fatalf("feed did not match: %s", feed)
	}
}

func Test_UnpackAndValidateCannedFragmentCorrupted(t *testing.T) {
	fragCose := make([]byte, len(fragmentCose))
	copy(fragCose, fragmentCose)

	offset := len(fragCose) / 2
	// corrupt the cose document (use the uncorrupted one as source in case we loop back to a good value)
	fragCose[offset] = fragmentCose[offset] + 1

	_, err := UnpackAndValidateCOSE1CertChain(fragCose)
	// expect it to fail
	if err == nil {
		t.Fatal("corrupted document passed validation")
	}
}

// Use CreateCoseSign1 to make a document that should match the one made by the makefile
func Test_CreateCoseSign1Fragment(t *testing.T) {
	var raw, err = CreateCoseSign1([]byte(fragmentRego), "TestIssuer", "TestFeed", "application/unknown+rego", []byte(certChainPEM), []byte(leafPrivatePem), "zero", cose.AlgorithmES384)
	if err != nil {
		t.Fatalf("CreateCoseSign1 failed: %s", err)
	}

	if len(raw) != len(fragmentCose) {
		t.Fatalf("created fragment length (%d) does not match expected (%d)", len(raw), len(fragmentCose))
	}

	for i := range raw {
		if raw[i] != fragmentCose[i] {
			t.Errorf("created fragment byte offset %d does not match expected", i)
		}
	}
}

func Test_OldCose(t *testing.T) {
	filename := "esrp.test.cose"
	cose, err := readFileBytes(filename)
	if err == nil {
		_, err = UnpackAndValidateCOSE1CertChain(cose)
	}
	if err != nil {
		t.Fatalf("validation of %s failed: %s", filename, err)
	}
}

func Test_DidX509(t *testing.T) {
	chainPEMBytes, err := os.ReadFile("chain.pem")
	if err != nil {
		t.Fatalf("failed to read PEM: %s", err)
	}
	chainPEM := string(chainPEMBytes)

	if _, err := MakeDidX509("sha256", 1, chainPEM, "subject:CN:Test Leaf (DO NOT TRUST)", true); err != nil {
		t.Fatalf("did:x509 creation failed: %s", err)
	}
}

// loadJWKSFile parses a minimal EC JWKS JSON file into a kid->PublicKey map.
func loadJWKSFile(t *testing.T, filename string) map[string]crypto.PublicKey {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("reading %s: %s", filename, err)
	}
	var set struct {
		Keys []struct {
			Kty, Crv, Kid, X, Y string
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("parsing %s: %s", filename, err)
	}
	out := map[string]crypto.PublicKey{}
	for i, k := range set.Keys {
		if k.Kty != "EC" {
			t.Fatalf("key %d: unsupported kty %q", i, k.Kty)
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
			t.Fatalf("key %d: unsupported crv %q", i, k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			t.Fatalf("key %d: decoding x: %s", i, err)
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			t.Fatalf("key %d: decoding y: %s", i, err)
		}
		out[k.Kid] = &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
	}
	return out
}

const (
	envelopeFile              = "esrp_transparent_hash_envelop.cose"
	envelopeJWKSFile          = "esrp_db_ledger_pub_keys.json"
	envelopeExpectedIssuer    = "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2"
	envelopeExpectedFeed      = "ContainerPlat-AMD-UVM"
	envelopeReceiptIssuer     = "esrp-cts-db.confidential-ledger.azure.com"
	envelopeReceiptKid        = "da7694f16def5a056ca96afb21e89a9450e4cc875e2de351da76d99544a3e849"
	envelopePreimageCType     = "application/octet-stream"
	envelopeReceiptCWTSubject = "scitt.ccf.signature.v1"
	graftedEnvelopeFile       = "esrp_with_grafted_receipt.cose"
	graftedEnvelopeJWKSFile   = "esrp_cp_ledger_pub_keys.json"
	signedTTLFile             = "aci-cc-ttl.ttl.cose"
	signedTTLJSONFile         = "aci-cc-ttl.ttl.json"
)

// Test_UnpackTransparentHashEnvelope verifies that a CWT-based envelope's
// issuer/feed are parsed correctly, the headers correctly stored in the
// resulting struct, and that the attached transparent receipt is parsed.
func Test_UnpackTransparentHashEnvelope(t *testing.T) {
	raw, err := os.ReadFile(envelopeFile)
	if err != nil {
		t.Fatalf("reading %s: %s", envelopeFile, err)
	}
	unpacked, err := UnpackAndValidateCOSE1CertChain(raw)
	if err != nil {
		t.Fatalf("UnpackAndValidateCOSE1CertChain failed: %s", err)
	}

	if unpacked.Issuer != envelopeExpectedIssuer {
		t.Errorf("Issuer = %q, want %q", unpacked.Issuer, envelopeExpectedIssuer)
	}
	if unpacked.Feed != envelopeExpectedFeed {
		t.Errorf("Feed = %q, want %q", unpacked.Feed, envelopeExpectedFeed)
	}

	// Hash envelope: payload hash alg (258) and preimage content type (259)
	// MUST be present in the protected header.
	hashAlg, ok := unpacked.Protected[COSE_Header_PayloadHashAlg]
	if !ok {
		t.Errorf("missing payload hash alg (label %d) in protected header", COSE_Header_PayloadHashAlg)
	} else if n, ok := asInt64(hashAlg); !ok || n != -43 {
		t.Errorf("payload hash alg = %v (%T), want -43", hashAlg, hashAlg)
	}
	preimage, ok := unpacked.Protected[COSE_Header_PreimageContentType]
	if !ok {
		t.Errorf("missing preimage content type (label %d) in protected header", COSE_Header_PreimageContentType)
	} else if s, ok := preimage.(string); !ok || s != envelopePreimageCType {
		t.Errorf("preimage content type = %v (%T), want %q", preimage, preimage, envelopePreimageCType)
	}

	// CWT Claims should carry the issuer (1) and subject (2).
	cwtVal, ok := unpacked.Protected[COSE_Header_CWTClaims]
	if !ok {
		t.Fatalf("missing CWTClaims (label %d) in protected header", COSE_Header_CWTClaims)
	}
	cwt, ok := cwtVal.(map[interface{}]interface{})
	if !ok {
		t.Fatalf("CWTClaims has wrong type: %T", cwtVal)
	}
	if iss, _ := cwt[CWT_Issuer].(string); iss != envelopeExpectedIssuer {
		t.Errorf("CWT iss = %q, want %q", iss, envelopeExpectedIssuer)
	}
	if sub, _ := cwt[CWT_Subject].(string); sub != envelopeExpectedFeed {
		t.Errorf("CWT sub = %q, want %q", sub, envelopeExpectedFeed)
	}

	// Receipts should be parsed (but not validated).
	if len(unpacked.Receipts) != 1 {
		t.Fatalf("len(Receipts) = %d, want 1", len(unpacked.Receipts))
	}
	r := unpacked.Receipts[0]
	if r.Issuer != envelopeReceiptIssuer {
		t.Errorf("receipt Issuer = %q, want %q", r.Issuer, envelopeReceiptIssuer)
	}
	if r.Kid != envelopeReceiptKid {
		t.Errorf("receipt Kid = %q, want %q", r.Kid, envelopeReceiptKid)
	}
	if len(r.Raw) == 0 {
		t.Errorf("receipt Raw is empty")
	}
	// Receipt should carry vds=CCF_LEDGER_SHA256.
	vds, ok := r.Message.Headers.Protected[COSE_Header_vds]
	if !ok {
		t.Fatalf("receipt missing vds (label %d)", COSE_Header_vds)
	}
	if n, ok := asInt64(vds); !ok || n != COSE_vds_CCF_LEDGER_SHA256 {
		t.Errorf("receipt vds = %v (%T), want %d", vds, vds, COSE_vds_CCF_LEDGER_SHA256)
	}
	// Receipt CWT should mention sub=scitt.ccf.signature.v1.
	rcwtVal, ok := r.Message.Headers.Protected[COSE_Header_CWTClaims]
	if !ok {
		t.Fatalf("receipt missing CWTClaims")
	}
	rcwt, ok := rcwtVal.(map[interface{}]interface{})
	if !ok {
		t.Fatalf("receipt CWTClaims has wrong type: %T", rcwtVal)
	}
	if sub, _ := rcwt[CWT_Subject].(string); sub != envelopeReceiptCWTSubject {
		t.Errorf("receipt CWT sub = %q, want %q", sub, envelopeReceiptCWTSubject)
	}
}

// Test_ValidateTransparentReceipt validates the CCF inclusion receipt
// attached to esrp_transparent_hash_envelop.cose using the bundled JWKS.
func Test_ValidateTransparentReceipt(t *testing.T) {
	raw, err := os.ReadFile(envelopeFile)
	if err != nil {
		t.Fatalf("reading %s: %s", envelopeFile, err)
	}
	unpacked, err := UnpackAndValidateCOSE1CertChain(raw)
	if err != nil {
		t.Fatalf("UnpackAndValidateCOSE1CertChain failed: %s", err)
	}
	if len(unpacked.Receipts) == 0 {
		t.Fatalf("no receipts attached to envelope")
	}
	keys := loadJWKSFile(t, envelopeJWKSFile)
	for i, r := range unpacked.Receipts {
		if err := r.Validate(keys); err != nil {
			t.Errorf("receipt %d Validate: %s", i, err)
		}
	}
}

// Test_ValidateTransparentReceiptMissingKey ensures validation fails cleanly
// when no key matches the receipt's kid.
func Test_ValidateTransparentReceiptMissingKey(t *testing.T) {
	raw, err := os.ReadFile(envelopeFile)
	if err != nil {
		t.Fatalf("reading %s: %s", envelopeFile, err)
	}
	unpacked, err := UnpackAndValidateCOSE1CertChain(raw)
	if err != nil {
		t.Fatalf("UnpackAndValidateCOSE1CertChain failed: %s", err)
	}
	if len(unpacked.Receipts) == 0 {
		t.Fatalf("no receipts attached to envelope")
	}
	err = unpacked.Receipts[0].Validate(map[string]crypto.PublicKey{})
	if err == nil {
		t.Fatal("Validate with empty keys unexpectedly succeeded")
	}
}

// Test_GraftedReceiptIsRejected loads esrp_with_grafted_receipt.cose, an envelope
// constructed by attaching a receipt for a different (unrelated) signed
// statement, and asserts that validation detects the mismatch. The receipt
// itself is valid, only the matching is wrong.
func Test_GraftedReceiptIsRejected(t *testing.T) {
	raw, err := os.ReadFile(graftedEnvelopeFile)
	if err != nil {
		t.Fatalf("reading %s: %s", graftedEnvelopeFile, err)
	}
	unpacked, err := UnpackAndValidateCOSE1CertChain(raw)
	if err != nil {
		t.Fatalf("UnpackAndValidateCOSE1CertChain failed: %s", err)
	}
	if len(unpacked.Receipts) == 0 {
		t.Fatalf("no receipts attached to envelope")
	}
	// Provide keys for the ledger that issued the donor receipt so that the
	// receipt's own signature verifies; the only remaining defence is the
	// missing binding check.
	keys := loadJWKSFile(t, graftedEnvelopeJWKSFile)
	if err := unpacked.Receipts[0].Validate(keys); err == nil {
		t.Errorf("grafted receipt unexpectedly passed validation: envelope/receipt mismatch is not checked")
	}
}

// Test_ParseSignedTTLKeySet tests TTL parsing with a pre-made TTL. It unwraps
// the COSE_Sign1 envelope, parses the TTL payload (which exercises
// ParseKeySetAsMap on the COSE_KeySet carried for each ledger), and compares the
// recovered keys against the committed JSON dump (produced by `sign1util
// dump-ttl`).
func Test_ParseSignedTTLKeySet(t *testing.T) {
	raw, err := os.ReadFile(signedTTLFile)
	if err != nil {
		t.Fatalf("reading %s: %s", signedTTLFile, err)
	}
	unpacked, err := UnpackAndValidateCOSE1CertChain(raw)
	if err != nil {
		t.Fatalf("UnpackAndValidateCOSE1CertChain failed: %s", err)
	}
	keysets, err := ParseTTLPayload(unpacked.Payload)
	if err != nil {
		t.Fatalf("ParseTTLPayload failed: %s", err)
	}

	// Load the expected keys from the committed JSON dump.
	expectedRaw, err := os.ReadFile(signedTTLJSONFile)
	if err != nil {
		t.Fatalf("reading %s: %s", signedTTLJSONFile, err)
	}
	var expected map[string]struct {
		Keys []struct {
			Kty, Kid, Crv, X, Y string
		}
	}
	if err := json.Unmarshal(expectedRaw, &expected); err != nil {
		t.Fatalf("parsing %s: %s", signedTTLJSONFile, err)
	}

	if len(keysets) != len(expected) {
		t.Fatalf("parsed %d ledgers, expected %d", len(keysets), len(expected))
	}
	for issuer, ledger := range expected {
		keys, ok := keysets[issuer]
		if !ok {
			t.Errorf("ledger %q present in JSON but missing from parsed TTL", issuer)
			continue
		}
		if len(keys) != len(ledger.Keys) {
			t.Errorf("ledger %q has %d keys, expected %d", issuer, len(keys), len(ledger.Keys))
		}
		for _, jwk := range ledger.Keys {
			gotPk, ok := keys[jwk.Kid]
			if !ok {
				t.Errorf("ledger %q missing expected kid %q", issuer, jwk.Kid)
				continue
			}
			wantPk := ecdsaPublicKeyFromXY(t, jwk.Crv, jwk.X, jwk.Y)
			eq, ok := gotPk.(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !eq.Equal(wantPk) {
				t.Errorf("ledger %q kid %q public key does not match expected", issuer, jwk.Kid)
			}
		}
	}
}

// ecdsaPublicKeyFromXY reconstructs an EC public key from its JWK curve name and
// base64url-encoded coordinates.
func ecdsaPublicKeyFromXY(t *testing.T, crv, x, y string) *ecdsa.PublicKey {
	t.Helper()
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		t.Fatalf("unsupported crv %q", crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		t.Fatalf("decoding x: %s", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		t.Fatalf("decoding y: %s", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
}
