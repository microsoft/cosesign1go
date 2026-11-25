package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Microsoft/cosesign1go/pkg/cosesign1"
	"github.com/fxamacker/cbor/v2"
	"github.com/urfave/cli"
	"github.com/veraison/go-cose"
)

// TCB reference info payloads are signed with this COSE content type. The
// version lives in the content type, so the payload has no version field.
const tcbReferenceInfoContentType = "application/vnd.tcb-reference-info.v1+cose"

// Top-level keys: TEE architecture.
const tcbInfoTEEArchAMDSEVSNP = 1

const (
	amdSEVSNPCPUIDLen = 4
	amdSEVSNPTCBLen   = 8
)

// tcbReferenceInfo is the JSON form, with CPUIDs and TCBs as lowercase hex.
type tcbReferenceInfo struct {
	AMDSEVSNP map[string]amdSEVSNPMinimumTCB `json:"amd_sev_snp"`
}

type amdSEVSNPMinimumTCB struct {
	CPUModelName string `json:"cpu_model_name"`
	TCB          string `json:"minimum_tcb"`
}

// tcbReferenceInfoCBOR is the wire form, with CPUIDs and TCBs as byte strings.
type tcbReferenceInfoCBOR struct {
	AMDSEVSNP map[cbor.ByteString]amdSEVSNPMinimumTCBCBOR `cbor:"1,keyasint"`
}

type amdSEVSNPMinimumTCBCBOR struct {
	CPUModelName string `cbor:"1,keyasint"`
	TCB          []byte `cbor:"2,keyasint"`
}

// Decodes a hex string, ensuring that the binary represented by it has
// the given length.
func decodeFixedHex(hexstr string, length int, fieldName string) ([]byte, error) {
	decoded, err := hex.DecodeString(hexstr)
	if err != nil || len(decoded) != length {
		return nil, fmt.Errorf("%s must contain exactly %d hexadecimal digits: %q", fieldName, 2*length, hexstr)
	}
	return decoded, nil
}

func tcbReferenceInfoToCBOR(info tcbReferenceInfo) (*tcbReferenceInfoCBOR, error) {
	if len(info.AMDSEVSNP) == 0 {
		return nil, fmt.Errorf("amd_sev_snp must not be empty")
	}
	result := &tcbReferenceInfoCBOR{AMDSEVSNP: map[cbor.ByteString]amdSEVSNPMinimumTCBCBOR{}}
	for cpuid, entry := range info.AMDSEVSNP {
		cpuidBytes, err := decodeFixedHex(cpuid, amdSEVSNPCPUIDLen, "CPUID")
		if err != nil {
			return nil, err
		}
		tcb, err := decodeFixedHex(entry.TCB, amdSEVSNPTCBLen, "TCB for CPUID "+cpuid)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(entry.CPUModelName) == "" {
			return nil, fmt.Errorf("cpu_model_name for CPUID %s must not be empty", cpuid)
		}
		key := cbor.ByteString(cpuidBytes)
		if _, exists := result.AMDSEVSNP[key]; exists {
			return nil, fmt.Errorf("duplicate CPUID %s", cpuid)
		}
		result.AMDSEVSNP[key] = amdSEVSNPMinimumTCBCBOR{CPUModelName: entry.CPUModelName, TCB: tcb}
	}
	return result, nil
}

func tcbReferenceInfoFromCBOR(info tcbReferenceInfoCBOR) (*tcbReferenceInfo, error) {
	result := tcbReferenceInfo{AMDSEVSNP: map[string]amdSEVSNPMinimumTCB{}}
	for cpuid, entry := range info.AMDSEVSNP {
		if len(cpuid) != amdSEVSNPCPUIDLen {
			return nil, fmt.Errorf("CPUID must be %d bytes, got %d", amdSEVSNPCPUIDLen, len(cpuid))
		}
		hexCPUID := hex.EncodeToString([]byte(cpuid))
		if len(entry.TCB) != amdSEVSNPTCBLen {
			return nil, fmt.Errorf("TCB for CPUID %s must be %d bytes, got %d", hexCPUID, amdSEVSNPTCBLen, len(entry.TCB))
		}
		result.AMDSEVSNP[hexCPUID] = amdSEVSNPMinimumTCB{CPUModelName: entry.CPUModelName, TCB: hex.EncodeToString(entry.TCB)}
	}
	return &result, nil
}

func encodeTCBReferenceInfo(data []byte) ([]byte, error) {
	var info tcbReferenceInfo
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding TCB reference info JSON: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing JSON value")
		}
		return nil, fmt.Errorf("unexpected trailing JSON data: %w", err)
	}
	wire, err := tcbReferenceInfoToCBOR(info)
	if err != nil {
		return nil, err
	}
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(wire)
}

func decodeTCBReferenceInfo(data []byte) (*tcbReferenceInfo, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty TCB reference info document")
	}
	// Unwrap for inspection only. Unlike dump-ttl, this does not verify signatures.
	if data[0]>>5 == 6 {
		var tag cbor.RawTag
		if err := cbor.Unmarshal(data, &tag); err != nil {
			return nil, fmt.Errorf("decoding COSE tag: %w", err)
		}
		if tag.Number != cosesign1.COSE_Sign1_Tag {
			return nil, fmt.Errorf("unexpected CBOR tag %d", tag.Number)
		}
		data = tag.Content
		if len(data) == 0 || data[0]>>5 != 4 {
			return nil, fmt.Errorf("COSE_Sign1 tag must wrap an array")
		}
	}
	if len(data) > 0 && data[0]>>5 == 4 {
		var msg cose.UntaggedSign1Message
		if err := msg.UnmarshalCBOR(data); err != nil {
			return nil, fmt.Errorf("decoding COSE_Sign1: %w", err)
		}
		if cty, ok := msg.Headers.Protected[cose.HeaderLabelContentType].(string); !ok || cty != tcbReferenceInfoContentType {
			return nil, fmt.Errorf("COSE_Sign1 protected header content type must be %q", tcbReferenceInfoContentType)
		}
		if msg.Payload == nil {
			return nil, fmt.Errorf("COSE_Sign1 payload must be attached")
		}
		data = msg.Payload
	}
	// Keys for unknown TEE architectures are ignored so new architectures can
	// be added without breaking existing consumers.
	var top struct {
		AMDSEVSNP cbor.RawMessage `cbor:"1,keyasint"`
	}
	topMode, err := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}).DecMode()
	if err != nil {
		return nil, err
	}
	if err := topMode.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("decoding TCB reference info CBOR: %w", err)
	}
	if top.AMDSEVSNP == nil {
		return nil, fmt.Errorf("missing AMD SEV-SNP (key %d) in TCB reference info", tcbInfoTEEArchAMDSEVSNP)
	}
	mode, err := (cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}).DecMode()
	if err != nil {
		return nil, err
	}
	var wire tcbReferenceInfoCBOR
	if err := mode.Unmarshal(top.AMDSEVSNP, &wire.AMDSEVSNP); err != nil {
		return nil, fmt.Errorf("decoding AMD SEV-SNP minimum TCBs: %w", err)
	}
	return tcbReferenceInfoFromCBOR(wire)
}

var createTCBReferenceInfoCmd = cli.Command{
	Name:  "create-tcb-reference-info",
	Usage: "encode TCB reference info JSON as an unsigned deterministic CBOR payload",
	Flags: []cli.Flag{
		cli.StringFlag{Name: "in", Usage: "input JSON file (required)", Required: true},
		cli.StringFlag{Name: "out", Usage: "output CBOR file (required)", Required: true},
	},
	Action: func(ctx *cli.Context) error {
		data, err := os.ReadFile(ctx.String("in"))
		if err != nil {
			return fmt.Errorf("reading TCB reference info: %w", err)
		}
		payload, err := encodeTCBReferenceInfo(data)
		if err != nil {
			return fmt.Errorf("encoding TCB reference info: %w", err)
		}
		if err := cosesign1.WriteBlob(ctx.String("out"), payload); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Fprintf(os.Stdout, "wrote TCB reference info to %s\n", ctx.String("out"))
		return nil
	},
}

var dumpTCBReferenceInfoCmd = cli.Command{
	Name:  "dump-tcb-reference-info",
	Usage: "print unsigned or COSE_Sign1-wrapped TCB reference info as JSON (does not verify signatures)",
	Flags: []cli.Flag{
		cli.StringFlag{Name: "in", Usage: "input CBOR or COSE_Sign1 file (required)", Required: true},
		cli.StringFlag{Name: "out", Usage: "output JSON file (default: stdout)"},
	},
	Action: func(ctx *cli.Context) error {
		data, err := os.ReadFile(ctx.String("in"))
		if err != nil {
			return fmt.Errorf("reading TCB reference info: %w", err)
		}
		info, err := decodeTCBReferenceInfo(data)
		if err != nil {
			return fmt.Errorf("decoding TCB reference info: %w", err)
		}
		rendered, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return fmt.Errorf("rendering TCB reference info as JSON: %w", err)
		}
		if out := ctx.String("out"); out != "" {
			if err := cosesign1.WriteBlob(out, rendered); err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}
		} else {
			fmt.Fprintf(os.Stdout, "%s\n", rendered)
		}
		return nil
	},
}
