package odoh

import (
	"bytes"
	"testing"
)

func TestEncodeEmptySlice(t *testing.T) {
	expectedBytes := []byte{0x00, 0x00}
	if !bytes.Equal(encodeLengthPrefixedSlice(nil), expectedBytes) {
		t.Fatalf("Result mismatch.")
	}
}

func TestEncodeLengthPrefixedSlice(t *testing.T) {
	testData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result := encodeLengthPrefixedSlice(testData)
	expectedBytes := []byte{0x00, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	if !bytes.Equal(result, expectedBytes) {
		t.Fatalf("Result mismatch.")
	}
}

func TestDecodeLengthPrefixedSlice(t *testing.T) {
	testData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result := encodeLengthPrefixedSlice(testData)
	decodedBytes, length, err := decodeLengthPrefixedSlice(result)
	if err != nil {
		t.Fatalf("Raised an error. Decoding error.")
	}
	if !bytes.Equal(testData, decodedBytes) {
		t.Fatalf("Decoding result mismatch.")
	}
	if len(testData)+2 != length {
		t.Fatalf("Incorrect length in the encoded message.")
	}
}
