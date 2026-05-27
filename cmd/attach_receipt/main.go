// attach_receipt rewrites a COSE_Sign1 envelope's unprotected `receipts`
// header (label 394), replacing it with either a single raw receipt blob or
// with the receipts copied from a donor COSE_Sign1 envelope.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"

	"github.com/Microsoft/cosesign1go/pkg/cosesign1"
)

func main() {
	in := flag.String("in", "", "input COSE_Sign1 envelope file")
	out := flag.String("out", "", "output COSE_Sign1 envelope file")
	donor := flag.String("donor", "", "donor COSE_Sign1 envelope to steal receipts from")
	receipt := flag.String("receipt", "", "raw COSE_Sign1 receipt blob to attach (alternative to --donor)")
	flag.Parse()

	if *in == "" || *out == "" || (*donor == "") == (*receipt == "") {
		fmt.Fprintln(os.Stderr, "usage: attach_receipt -in IN.cose -out OUT.cose (-donor DONOR.cose | -receipt R.bin)")
		os.Exit(2)
	}

	inBytes, err := os.ReadFile(*in)
	check(err)

	var receipts []interface{}
	if *donor != "" {
		dBytes, err := os.ReadFile(*donor)
		check(err)
		receipts, err = extractReceipts(dBytes)
		check(err)
		if len(receipts) == 0 {
			die("donor envelope has no receipts in unprotected header")
		}
	} else {
		rBytes, err := os.ReadFile(*receipt)
		check(err)
		receipts = []interface{}{rBytes}
	}

	patched, err := replaceReceipts(inBytes, receipts)
	check(err)
	check(os.WriteFile(*out, patched, 0o644))
}

// rawSign1 is a COSE_Sign1 represented as a 4-element CBOR array, keeping
// each element as a RawMessage so the protected bstr, payload, and signature
// can be preserved verbatim across re-encoding.
type rawSign1 struct {
	_              struct{} `cbor:",toarray"`
	Protected      cbor.RawMessage
	Unprotected    map[interface{}]interface{}
	Payload        cbor.RawMessage
	Signature      cbor.RawMessage
}

// decodeSign1 parses a COSE_Sign1, stripping the optional CBOR tag (18).
func decodeSign1(data []byte) (rawSign1, bool, error) {
	// COSE_Sign1 tag is encoded as 0xd2 (major type 6, value 18).
	hadTag := len(data) > 0 && data[0] == 0xd2
	var msg rawSign1
	if err := cbor.Unmarshal(data, &msg); err != nil {
		return rawSign1{}, false, fmt.Errorf("decoding COSE_Sign1: %w", err)
	}
	return msg, hadTag, nil
}

func extractReceipts(data []byte) ([]interface{}, error) {
	msg, _, err := decodeSign1(data)
	if err != nil {
		return nil, err
	}
	val, ok := msg.Unprotected[int64(cosesign1.COSE_Header_Receipts)]
	if !ok {
		// fxamacker/cbor may decode small int keys as uint64.
		val, ok = msg.Unprotected[uint64(cosesign1.COSE_Header_Receipts)]
	}
	if !ok {
		return nil, nil
	}
	arr, ok := val.([]interface{})
	if !ok {
		return nil, fmt.Errorf("receipts header is not an array (got %T)", val)
	}
	return arr, nil
}

func replaceReceipts(data []byte, receipts []interface{}) ([]byte, error) {
	msg, hadTag, err := decodeSign1(data)
	if err != nil {
		return nil, err
	}
	// Delete any existing receipts entry (under either int key type) then set.
	delete(msg.Unprotected, int64(cosesign1.COSE_Header_Receipts))
	delete(msg.Unprotected, uint64(cosesign1.COSE_Header_Receipts))
	msg.Unprotected[int64(cosesign1.COSE_Header_Receipts)] = receipts

	encOpts := cbor.CoreDetEncOptions()
	encOpts.Sort = cbor.SortNone
	em, err := encOpts.EncMode()
	if err != nil {
		return nil, err
	}
	body, err := em.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("encoding patched COSE_Sign1: %w", err)
	}
	if hadTag {
		return em.Marshal(cbor.Tag{Number: 18, Content: cbor.RawMessage(body)})
	}
	return body, nil
}

func check(err error) {
	if err != nil {
		die(err.Error())
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "attach_receipt:", msg)
	os.Exit(1)
}
