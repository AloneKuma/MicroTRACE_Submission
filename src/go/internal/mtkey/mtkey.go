// Package mtkey encodes and decodes MicroTRACE Kafka record keys
// (spec/kafka/kafka-contract.md, "Keys"). It is a port of encode_key and
// decode_key in spec/tools/mtcodec.py and must produce identical bytes.
package mtkey

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Version is the key encoding version (KEY_VERSION in mtcodec.py).
const Version = 0

// Component is one key component: its KeyComponent code and value.
type Component struct {
	Code  uint8
	Value string
}

// Encode returns "MT", version, key type (u16 BE), component count, then per
// component: code, u32 BE length, UTF-8 value.
func Encode(keyType uint16, comps []Component) ([]byte, error) {
	if len(comps) > 255 {
		return nil, errors.New("too many key components")
	}
	out := []byte{'M', 'T', Version, 0, 0, byte(len(comps))}
	binary.BigEndian.PutUint16(out[3:5], keyType)
	for _, c := range comps {
		if c.Value == "" {
			return nil, errors.New("absent key component; record must not be routed")
		}
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(c.Value)))
		out = append(out, c.Code)
		out = append(out, l[:]...)
		out = append(out, c.Value...)
	}
	return out, nil
}

// Decode parses a key produced by Encode.
func Decode(data []byte) (version uint8, keyType uint16, comps []Component, err error) {
	if len(data) < 6 || data[0] != 'M' || data[1] != 'T' {
		return 0, 0, nil, errors.New("bad magic")
	}
	version = data[2]
	keyType = binary.BigEndian.Uint16(data[3:5])
	count := int(data[5])
	pos := 6
	for i := 0; i < count; i++ {
		if pos+5 > len(data) {
			return 0, 0, nil, fmt.Errorf("component %d truncated", i)
		}
		code := data[pos]
		n := int(binary.BigEndian.Uint32(data[pos+1 : pos+5]))
		if pos+5+n > len(data) {
			return 0, 0, nil, fmt.Errorf("component %d truncated", i)
		}
		comps = append(comps, Component{Code: code, Value: string(data[pos+5 : pos+5+n])})
		pos += 5 + n
	}
	if pos != len(data) {
		return 0, 0, nil, errors.New("trailing bytes")
	}
	return version, keyType, comps, nil
}
