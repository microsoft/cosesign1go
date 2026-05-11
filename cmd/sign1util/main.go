package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/Microsoft/cosesign1go/pkg/cosesign1"
	didx509resolver "github.com/Microsoft/didx509go/pkg/did-x509-resolver"
	"github.com/urfave/cli"
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

// fetchIssuerJWKS GETs https://<issuer>/jwks and returns the keys keyed by
// their `kid`.
//
// CCF nodes serve TLS using a self-signed certificate whose authenticity is
// backed by SNP attestation rather than a public CA, so TLS verification is
// skipped here. A production verifier should validate the node's attestation
// evidence instead.
func fetchIssuerJWKS(issuer string) (map[string]crypto.PublicKey, error) {
	url := "https://" + issuer + "/jwks"
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // CCF uses self-signed certs
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
		out[k.Kid] = pub
	}
	return out, nil
}

// fetchCCFReceiptKeys looks up each receipt's issuer in the envelope, fetches
// the matching JWKS, and returns a kid->PublicKey map covering all receipts.
func fetchCCFReceiptKeys(unpacked *cosesign1.UnpackedCoseSign1) (map[string]crypto.PublicKey, error) {
	infos, err := cosesign1.CCFReceiptsInfo(unpacked)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	keys := map[string]crypto.PublicKey{}
	for _, info := range infos {
		if info.Issuer == "" {
			return nil, fmt.Errorf("receipt has no issuer; cannot fetch JWKS")
		}
		if seen[info.Issuer] {
			continue
		}
		seen[info.Issuer] = true
		issuerKeys, err := fetchIssuerJWKS(info.Issuer)
		if err != nil {
			return nil, err
		}
		for kid, k := range issuerKeys {
			keys[kid] = k
		}
	}
	return keys, nil
}

// formatValue formats a CBOR-decoded value in a human-readable way that
// preserves integer keys (unlike JSON).
func formatValue(v interface{}) string {
	switch v := v.(type) {
	case map[interface{}]interface{}:
		parts := make([]string, 0, len(v))
		for key, val := range v {
			parts = append(parts, fmt.Sprintf("%s: %s", formatValue(key), formatValue(val)))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, val := range v {
			parts = append(parts, formatValue(val))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []byte:
		return fmt.Sprintf("0x%x", v)
	case string:
		return fmt.Sprintf("%q", v)
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func printKeyValue(indent string, k, v interface{}) {
	fmt.Fprintf(os.Stdout, "%s%v: %s\n", indent, k, formatValue(v))
}

func checkCoseSign1(inputFilename string, chainFilename string, didString string, verbose bool) (*cosesign1.UnpackedCoseSign1, error) {
	coseBlob, err := os.ReadFile(inputFilename)
	if err != nil {
		return nil, err
	}

	var chainPEM []byte
	var chainPEMString string
	if chainFilename != "" {
		chainPEM, err = os.ReadFile(chainFilename)
		if err != nil {
			return nil, err
		}
		chainPEMString = string(chainPEM[:])
	}

	unpacked, err := cosesign1.UnpackAndValidateCOSE1CertChain(coseBlob)
	if err != nil {
		fmt.Fprintf(os.Stdout, "checkCoseSign1 failed - %s\n", err)
		return nil, err
	}

	receipts := make([][]byte, 0)

	fmt.Fprint(os.Stdout, "checkCoseSign1 passed\n")

	// If the envelope carries COSE Receipts, validate them against the CCF
	// ledger profile.
	if _, hasReceipts := unpacked.Unprotected[cosesign1.COSE_Header_Receipts]; hasReceipts {
		keys, err := fetchCCFReceiptKeys(unpacked)
		if err != nil {
			fmt.Fprintf(os.Stdout, "fetching CCF receipt keys failed - %s\n", err)
			return nil, fmt.Errorf("fetching CCF receipt keys: %w", err)
		}
		if err := cosesign1.ValidateCCFReceipt(unpacked, keys); err != nil {
			fmt.Fprintf(os.Stdout, "CCF receipt validation failed - %s\n", err)
			return nil, fmt.Errorf("CCF receipt validation failed: %w", err)
		}
		fmt.Fprint(os.Stdout, "CCF receipt validation passed\n")
	}
	if verbose {
		fmt.Fprintf(os.Stdout, "iss: %s\n", unpacked.Issuer)
		fmt.Fprintf(os.Stdout, "feed: %s\n", unpacked.Feed)
		fmt.Fprintf(os.Stdout, "cty: %s\n", unpacked.ContentType)
		fmt.Fprintf(os.Stdout, "pubkey: %s\n", unpacked.Pubkey)
		fmt.Fprintf(os.Stdout, "pubcert: %s\n", unpacked.Pubcert)
		fmt.Fprintf(os.Stdout, "all protected headers:\n")
		isHashEnvelop := false
		for k, v := range unpacked.Protected {
			if k, ok := k.(int64); ok && (k == cosesign1.COSE_Header_x5chain || k == cosesign1.COSE_Header_x5t) {
				fmt.Fprintf(os.Stdout, "  %d: ...\n", k)
				continue
			}
			if k, ok := k.(int64); ok && k == cosesign1.COSE_Header_PreimageContentType {
				isHashEnvelop = true
			}
			printKeyValue("  ", k, v)
		}
		fmt.Fprintf(os.Stdout, "all unprotected headers:\n")
	a:
		for k, v := range unpacked.Unprotected {
			if k, ok := k.(int64); ok && k == cosesign1.COSE_Header_Receipts {
				fmt.Fprintf(os.Stdout, "  %d: ...", k)
				receiptsArr, ok := v.([]interface{})
				if !ok {
					fmt.Fprintf(os.Stdout, " (failed to parse receipts)\n")
					continue
				}
				for i, receipt := range receiptsArr {
					receiptBytes, ok := receipt.([]byte)
					if !ok {
						fmt.Fprintf(os.Stdout, "  receipt %d failed to parse\n", i)
						continue a
					}
					receipts = append(receipts, receiptBytes)
				}
				fmt.Fprintf(os.Stdout, "\n")
				continue
			}
			printKeyValue("  ", k, v)
		}
		fmt.Fprintf(os.Stdout, "payload:\n")
		if isHashEnvelop {
			fmt.Fprintf(os.Stdout, "%x", unpacked.Payload[:])
		} else {
			fmt.Fprintf(os.Stdout, "%s", string(unpacked.Payload))
		}
		fmt.Fprintf(os.Stdout, "\n")
	}
	if len(didString) > 0 {
		if len(chainPEMString) == 0 {
			chainPEMString = unpacked.ChainPem
		}
		didDoc, err := didx509resolver.Resolve(chainPEMString, didString, true)
		if err == nil {
			fmt.Fprintf(os.Stdout, "DID resolvers passed:\n%s\n", didDoc)
		} else {
			// all the error paths return an empty string, so we can just print the error
			fmt.Fprintf(os.Stdout, "DID resolvers failed: err: %s\n", err.Error())
		}
	}

	for i, receipt := range receipts {
		var msg cose.Sign1Message
		err := msg.UnmarshalCBOR(receipt)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stdout, "receipt %d:\n", i)
		fmt.Fprintf(os.Stdout, "  protected headers:\n")
		for k, v := range msg.Headers.Protected {
			if k, ok := k.(int64); ok && k == cosesign1.COSE_Header_kid {
				fmt.Fprintf(os.Stdout, "    %d: %q\n", k, v.([]byte))
				continue
			}
			printKeyValue("    ", k, v)
		}
		fmt.Fprintf(os.Stdout, "  unprotected headers:\n")
		for k, v := range msg.Headers.Unprotected {
			if k, ok := k.(int64); ok && k == cosesign1.COSE_Header_vdp {
				m, ok := v.(map[interface{}]interface{})
				if !ok {
					fmt.Fprintf(os.Stdout, "    %d: ... (failed to parse)\n", k)
					continue
				}
				fmt.Fprintf(os.Stdout, "    %d:\n", k)
				for k, v := range m {
					if k, ok := k.(int64); ok && k == cosesign1.COSE_ProofInclusion {
						fmt.Fprintf(os.Stdout, "      %d: inclusion proof\n", k)
						continue
					}
					if k, ok := k.(int64); ok && k == cosesign1.COSE_ProofConsistency {
						fmt.Fprintf(os.Stdout, "      %d: consistency proof\n", k)
						continue
					}
					printKeyValue("      ", k, v)
				}
				continue
			}
			printKeyValue("    ", k, v)
		}
		fmt.Fprintf(os.Stdout, "  payload: %q\n", msg.Payload)
		continue
	}

	return unpacked, err
}

var createCmd = cli.Command{
	Name:  "create",
	Usage: "",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "claims",
			Usage: "filename of payload",
			Value: "fragment.rego",
		},
		cli.StringFlag{
			Name:  "content-type",
			Usage: "payload content type",
			Value: "application/unknown+json",
		},
		cli.StringFlag{
			Name:  "chain",
			Usage: "key or cert file to use (pem)",
			Value: "chain.pem",
		},
		cli.StringFlag{
			Name:  "key",
			Usage: "key to sign with - private key of the leaf of the chain",
			Value: "key.pem",
		},
		cli.StringFlag{
			Name:     "algo",
			Usage:    "PS256, PS384 etc (required)",
			Required: true,
		},
		cli.StringFlag{
			Name:  "out",
			Usage: "output file (default: out.cose)",
			Value: "out.cose",
		},
		cli.StringFlag{
			Name:  "salt",
			Usage: "salt type [rand|zero] (default: rand)",
			Value: "rand",
		},
		cli.StringFlag{
			Name: "issuer",
			Usage: "the party making the claims (optional). See https://ietf-scitt.github." +
				"io/draft-birkholz-scitt-architecture/draft-birkholz-scitt-architecture.html#name-terminology",
		},
		cli.StringFlag{
			Name:  "feed",
			Usage: "identifier for an artifact within the scope of an issuer (optional)",
		},
		cli.BoolFlag{
			Name:  "verbose,v",
			Usage: "verbose output (optional)",
		},
	},
	Action: func(ctx *cli.Context) error {
		payloadBlob, err := os.ReadFile(ctx.String("claims"))
		if err != nil {
			return err
		}
		keyPem, err := os.ReadFile(ctx.String("key"))
		if err != nil {
			return err
		}
		chainPem, err := os.ReadFile(ctx.String("chain"))
		if err != nil {
			return err
		}
		algo, err := cosesign1.StringToAlgorithm(ctx.String("algo"))
		if err != nil {
			return err
		}

		raw, err := cosesign1.CreateCoseSign1(
			payloadBlob,
			ctx.String("issuer"),
			ctx.String("feed"),
			ctx.String("content-type"),
			chainPem,
			keyPem,
			ctx.String("salt"),
			algo,
		)
		if err != nil {
			return fmt.Errorf("create failed: %w", err)
		}

		err = cosesign1.WriteBlob(ctx.String("out"), raw)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Fprint(os.Stdout, "create completed\n")
		return nil
	},
}

var checkCmd = cli.Command{
	Name:  "check",
	Usage: "",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "in",
			Usage: "input COSE Sign1 file (default: input.cose)",
			Value: "input.cose",
		},
		cli.StringFlag{
			Name:  "chain",
			Usage: "key or cert file to use (pem) (optional)",
		},
		cli.StringFlag{
			Name:  "did",
			Usage: "DID x509 string to resolve against cert chain (optional)",
		},
		cli.BoolFlag{
			Name:  "verbose",
			Usage: "verbose output (optional)",
		},
	},
	Action: func(ctx *cli.Context) error {
		_, err := checkCoseSign1(
			ctx.String("in"),
			ctx.String("chain"),
			ctx.String("did"),
			ctx.Bool("verbose"),
		)
		if err != nil {
			return fmt.Errorf("failed check: %w", err)
		}
		return nil
	},
}

var printCmd = cli.Command{
	Name:  "print",
	Usage: "",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "in",
			Usage: "input COSE Sign1 file",
			Value: "input.cose",
		},
	},
	Action: func(ctx *cli.Context) error {
		_, err := checkCoseSign1(ctx.String("in"), "", "", true)
		if err != nil {
			return fmt.Errorf("failed verbose checkCoseSign1: %w", err)
		}
		return nil
	},
}

var leafCmd = cli.Command{
	Name:  "leaf",
	Usage: "",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "in",
			Usage: "input COSE Sign1 file",
			Value: "input.cose",
		},
		cli.StringFlag{
			Name:  "keyout",
			Usage: "leaf key output file",
			Value: "leafkey.pem",
		},
		cli.StringFlag{
			Name:  "certout",
			Usage: "leaf cert output file",
			Value: "leafcert.pem",
		},
		cli.BoolFlag{
			Name:  "verbose",
			Usage: "print information about COSE Sign1 document",
		},
	},
	Action: func(ctx *cli.Context) error {
		inputFilename := ctx.String("in")
		outputKeyFilename := ctx.String("keyout")
		outputCertFilename := ctx.String("certout")
		unpacked, err := checkCoseSign1(
			inputFilename,
			"",
			"",
			ctx.Bool("verbose"),
		)
		if err != nil {
			return fmt.Errorf("reading the COSE Sign1 from %s failed: %w", inputFilename, err)
		}

		// fixme(maksiman): instead of just printing the error, consider returning
		// it right away and skipping cert writing.
		keyWriteErr := cosesign1.WriteString(outputKeyFilename, unpacked.Pubkey)
		if keyWriteErr != nil {
			fmt.Fprintf(os.Stderr, "writing the leaf pub key to %s failed: %s\n", outputKeyFilename, keyWriteErr)
		}
		certWriteErr := cosesign1.WriteString(outputCertFilename, unpacked.Pubcert)
		if certWriteErr != nil {
			fmt.Fprintf(os.Stderr, "writing the leaf cert to %s failed: %s", outputCertFilename, certWriteErr)
		}

		var retErr error
		if keyWriteErr != nil {
			retErr = fmt.Errorf("key write failed: %s", retErr)
		}
		if certWriteErr != nil {
			if retErr != nil {
				return fmt.Errorf("cert write failed: %s: %s", certWriteErr, retErr)
			}
			return fmt.Errorf("cert write failed: %s", certWriteErr)
		}
		return nil
	},
}

var didX509Cmd = cli.Command{
	Name:  "did-x509",
	Usage: "",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "in",
			Usage: "input file",
		},
		cli.StringFlag{
			Name:  "fingerprint-algorithm",
			Usage: "hash algorithm for certificate fingerprints",
			Value: "sha256",
		},
		cli.StringFlag{
			Name:  "chain",
			Usage: "certificate chain to use (pem)",
		},
		cli.IntFlag{
			Name:  "index, i",
			Usage: "index of the certificate fingerprint in the chain",
			Value: 1,
		},
		cli.StringFlag{
			Name:  "policy",
			Usage: "did:509 policy, can be one of [cn|eku|custom]",
			Value: "cn",
		},
		cli.BoolFlag{
			Name:  "verbose",
			Usage: "verbose output (optional)",
		},
	},
	Action: func(ctx *cli.Context) error {
		chainFilename := ctx.String("chain")
		inputFilename := ctx.String("in")
		if len(chainFilename) > 0 && len(inputFilename) > 0 {
			return fmt.Errorf("cannot specify chain with cose file - it comes from the chain in the file")
		}
		var chainPEM string
		if len(chainFilename) > 0 {
			chainPEMBytes, err := os.ReadFile(chainFilename)
			if err != nil {
				return err
			}
			chainPEM = string(chainPEMBytes)
		}
		if len(inputFilename) > 0 {
			unpacked, err := checkCoseSign1(inputFilename, "", "", true)
			if err != nil {
				return err
			}
			chainPEM = unpacked.ChainPem
		}
		r, err := cosesign1.MakeDidX509(
			ctx.String("fingerprint-algorithm"),
			ctx.Int("index"),
			chainPEM,
			ctx.String("policy"),
			ctx.Bool("verbose"),
		)
		if err != nil {
			return fmt.Errorf("failed make DID: %w", err)
		}
		fmt.Fprint(os.Stdout, r)
		return nil
	},
}

var chainCmd = cli.Command{
	Name:  "chain",
	Usage: "",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "in",
			Usage: "input COSE Sign1 file",
			Value: "input.cose",
		},
		cli.StringFlag{
			Name:  "out",
			Usage: "output chain PEM text file",
		},
	},
	Action: func(ctx *cli.Context) error {
		pems, err := cosesign1.ParsePemChain(ctx.String("in"))
		if err != nil {
			return err
		}
		if len(ctx.String("out")) > 0 {
			return cosesign1.WriteString(ctx.String("out"), strings.Join(pems, "\n"))
		} else {
			fmt.Fprintf(os.Stdout, "%s\n", strings.Join(pems, "\n"))
			return nil
		}
	},
}

func main() {
	app := cli.NewApp()
	app.Name = "sign1util"
	app.Commands = []cli.Command{
		createCmd,
		checkCmd,
		printCmd,
		leafCmd,
		didX509Cmd,
		chainCmd,
	}

	if err := app.Run(os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
