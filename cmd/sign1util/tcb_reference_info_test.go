package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/urfave/cli"
)

// Copy of the reference info committed in Compute-ACI.
var referenceInfoJSON = func() string {
	data, err := os.ReadFile("tcb_reference_info.json")
	if err != nil {
		panic(err)
	}
	return string(data)
}()

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTCBReferenceInfoMatchesEverParse(t *testing.T) {
	// Captured from the cborrs generator for referenceInfoJSON.
	expected := mustHex(t,
		"a101a24400a00f11a201781f414d44204550594320373736332036342d436f72"+
			"652050726f636573736f720248db180000000000044400a10f11a201781f414d"+
			"44204550594320395637342038302d436f72652050726f636573736f72024854"+
			"1700000000000a")
	actual, err := encodeTCBReferenceInfo([]byte(referenceInfoJSON))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("CBOR differs from EverParse:\ngot  %x\nwant %x", actual, expected)
	}
	var reordered tcbReferenceInfo
	if err := json.Unmarshal([]byte(referenceInfoJSON), &reordered); err != nil {
		t.Fatal(err)
	}
	compact, err := json.Marshal(reordered)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeTCBReferenceInfo(compact)
	if err != nil || !bytes.Equal(actual, again) {
		t.Fatalf("encoding depends on JSON formatting: %v", err)
	}
}

func coseEnvelope(t *testing.T, protected map[int]interface{}, payload []byte) []interface{} {
	t.Helper()
	header, err := cbor.Marshal(protected)
	if err != nil {
		t.Fatal(err)
	}
	return []interface{}{header, map[int]interface{}{}, payload, bytes.Repeat([]byte{0x5a}, 96)}
}

func TestDumpTCBReferenceInfo(t *testing.T) {
	payload, err := encodeTCBReferenceInfo([]byte(referenceInfoJSON))
	if err != nil {
		t.Fatal(err)
	}
	var expected tcbReferenceInfo
	if err := json.Unmarshal([]byte(referenceInfoJSON), &expected); err != nil {
		t.Fatal(err)
	}
	envelope := coseEnvelope(t, map[int]interface{}{1: -35, 3: tcbReferenceInfoContentType}, payload)
	for name, input := range map[string]interface{}{
		"raw":      cbor.RawMessage(payload),
		"untagged": envelope,
		"tagged":   cbor.Tag{Number: 18, Content: envelope},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := cbor.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			info, err := decodeTCBReferenceInfo(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*info, expected) {
				t.Fatalf("unexpected decoded info: %+v", info)
			}
		})
	}
}

func TestTCBReferenceInfoRejectsInvalidInput(t *testing.T) {
	for _, invalid := range []string{
		`{}`,
		`{"amd_sev_snp": {}}`,
		strings.Replace(referenceInfoJSON, `"amd_sev_snp": {`, `"version": 1, "amd_sev_snp": {`, 1),
		strings.Replace(referenceInfoJSON, `"00a00f11"`, `"00a00f"`, 1),
		strings.Replace(referenceInfoJSON, `"db18000000000004"`, `"db18"`, 1),
		strings.Replace(referenceInfoJSON, `"db18000000000004"`, `"db1800000000000g"`, 1),
		strings.Replace(referenceInfoJSON, `"AMD EPYC 7763 64-Core Processor"`, `" "`, 1),
		strings.Replace(referenceInfoJSON, `"cpu_model_name":`, `"typo":`, 1),
		strings.Replace(referenceInfoJSON, `"minimum_tcb":`, `"tcb":`, 1),
		referenceInfoJSON + `{}`,
		referenceInfoJSON + ` garbage`,
	} {
		if _, err := encodeTCBReferenceInfo([]byte(invalid)); err == nil {
			t.Errorf("accepted invalid JSON: %s", invalid)
		}
	}
	payload, err := encodeTCBReferenceInfo([]byte(referenceInfoJSON))
	if err != nil {
		t.Fatal(err)
	}
	cpuid := "4400a00f11"
	model := "6141" // "A"
	tcb := "48db18000000000004"
	doc := func(cpuidKey, inner string) []byte { return mustHex(t, "a101a1"+cpuidKey+inner) }
	untaggedWith := func(protected map[int]interface{}) []byte {
		raw, err := cbor.Marshal(coseEnvelope(t, protected, payload))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, invalid := range [][]byte{
		nil,
		[]byte(referenceInfoJSON),
		append(append([]byte{}, payload...), 0x00),
		{0xa0},                         // Missing AMD SEV-SNP map.
		{0xa2, 0x01, 0xa0, 0x01, 0xa0}, // Duplicate top-level key.
		{0xa2, 0x02, 0xa0, 0x02, 0xa0}, // Duplicate unknown top-level key.
		mustHex(t, "a101a2"+cpuid+"a2"+"01"+model+"02"+tcb+cpuid+"a2"+"01"+model+"02"+tcb), // Duplicate CPUID.
		doc(cpuid, "a3"+"01"+model+"02"+tcb+"01"+model),                                    // Duplicate field.
		{0xa1, 0x02, 0xa0},                                                                   // Only an unknown TEE architecture.
		doc(cpuid, "a101"+model),                                                             // Missing TCB.
		doc("4300a00f", "a2"+"01"+model+"02"+tcb),                                            // Short CPUID.
		doc("683030613030663131", "a2"+"01"+model+"02"+tcb),                                  // Text CPUID.
		doc(cpuid, "a2"+"01"+model+"02"+"47db1800000000"),                                    // Short TCB.
		doc(cpuid, "a2"+"01"+model+"02"+"70"+hex.EncodeToString([]byte("db18000000000004"))), // Text TCB.
		doc(cpuid, "a3"+"01"+model+"02"+tcb+"03"+model),                                      // Unknown field.
		{0x84, 0x40, 0xa0, 0xf6, 0x40},                                                       // Detached COSE payload, no cty.
		untaggedWith(map[int]interface{}{1: -35}),                                            // Missing content type.
		untaggedWith(map[int]interface{}{1: -35, 3: "application/cbor"}),
		{0xc1, 0x00},                     // Unexpected tag.
		append([]byte{0xd2}, payload...), // Tag 18 must wrap an envelope, not a payload map.
	} {
		if _, err := decodeTCBReferenceInfo(invalid); err == nil {
			t.Errorf("accepted invalid CBOR: %x", invalid)
		}
	}
	for _, valid := range []string{"a2" + "01" + model + "02" + tcb, "a2" + "02" + tcb + "01" + model} {
		if _, err := decodeTCBReferenceInfo(doc(cpuid, valid)); err != nil {
			t.Fatalf("rejected valid document %s: %v", valid, err)
		}
	}
	// Unknown top-level keys of any type are ignored.
	expected, err := decodeTCBReferenceInfo(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{"02a0", "6178820102", "02" + "a1" + cpuid + "01", "02c100", "02f820", "02f97e00"} {
		withExtra := append(append([]byte{0xa2}, payload[1:]...), mustHex(t, extra)...)
		info, err := decodeTCBReferenceInfo(withExtra)
		if err != nil {
			t.Fatalf("rejected unknown top-level key %s: %v", extra, err)
		}
		if !reflect.DeepEqual(info, expected) {
			t.Fatalf("unknown top-level key %s changed decoding: %+v", extra, info)
		}
	}
}

func TestTCBReferenceInfoCommands(t *testing.T) {
	dir := t.TempDir()
	input, binary, output := filepath.Join(dir, "in.json"), filepath.Join(dir, "out.bin"), filepath.Join(dir, "out.json")
	if err := os.WriteFile(input, []byte(referenceInfoJSON), 0600); err != nil {
		t.Fatal(err)
	}
	app := cli.NewApp()
	app.Commands = []cli.Command{createTCBReferenceInfoCmd, dumpTCBReferenceInfoCmd}
	for _, args := range [][]string{
		{"sign1util", "create-tcb-reference-info", "--in", input, "--out", binary},
		{"sign1util", "dump-tcb-reference-info", "--in", binary, "--out", output},
	} {
		if err := app.Run(args); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var got, expected map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(referenceInfoJSON), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("command round trip differs: %+v", got)
	}
}
