package cosesign1

import (
	"crypto"

	"github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	cose "github.com/veraison/go-cose"
)

// Parses a COSE_KeySet, which is a CBOR array of raw COSE_Key objects, into a
// map from key IDs to public keys, to be used for receipt validation.
//
// Reference: https://www.rfc-editor.org/rfc/rfc9052.html#name-cose-keys
func ParseKeySetAsMap(data []byte) (map[string]crypto.PublicKey, error) {
	var rawKeys []cbor.RawMessage
	if err := cbor.Unmarshal(data, &rawKeys); err != nil {
		return nil, errors.Wrap(err, "Failed to parse the COSE_KeySet")
	}
	if len(rawKeys) == 0 {
		return nil, errors.New("empty COSE Key Set")
	}
	var lastKeyError error
	keys := make(map[string]crypto.PublicKey)
	for i, raw := range rawKeys {
		// From RFC: Each element in a COSE Key Set MUST be processed
		// independently. If one element in a COSE Key Set is either malformed
		// or uses a key that is not understood by an application, that key is
		// ignored, and the other keys are processed normally.
		var k cose.Key
		if err := k.UnmarshalCBOR(raw); err != nil {
			logrus.Warnf("Failed to parse element %d of the COSE Key Set: %v", i, err)
			lastKeyError = errors.Wrapf(err, "UnmarshalCBOR element %d", i)
			continue
		}
		kid := string(k.ID)
		pk, err := k.PublicKey()
		if err != nil {
			logrus.Warnf("Failed to construct public key from element %d of the COSE Key Set (kid=%q): %v", i, kid, err)
			lastKeyError = errors.Wrapf(err, "construct PublicKey from element %d", i)
			continue
		}
		if _, exists := keys[kid]; exists {
			logrus.Warnf("Parsing element %d of the COSE Key Set: Key with ID %q already seen earlier, ignoring this one", i, kid)
			continue
		}
		keys[kid] = pk
	}
	if len(keys) == 0 {
		logrus.Errorf("Failed to parse any element of the provided COSE Key Set")
		return nil, lastKeyError
	}
	return keys, nil
}
