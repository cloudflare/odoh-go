// The MIT License
//
// Copyright (c) 2019-2020, Cloudflare, Inc. and Apple, Inc. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package odoh

import (
	"bytes"
	"testing"
)

func TestObliviousMessageMarshalEmptyKeyId(t *testing.T) {
	testMessage := []byte{0x06, 0x07, 0x08, 0x09}
	message := ObliviousDNSMessage{
		MessageType:      0xFF,
		KeyID:            nil,
		EncryptedMessage: testMessage,
	}

	serializedMessage := message.Marshal()
	expectedBytes := []byte{0xFF}
	expectedBytes = append(expectedBytes, []byte{0x00, 0x00}...) // empty key ID
	expectedBytes = append(expectedBytes, []byte{0x00, 0x04}...) // non-empty message
	expectedBytes = append(expectedBytes, testMessage...)
	if !bytes.Equal(serializedMessage, expectedBytes) {
		t.Fatalf("Marshalling mismatch in the encoding. Got %x, received %x", serializedMessage, expectedBytes)
	}
}

func TestObliviousMessageMarshalEmptyMessage(t *testing.T) {
	testKeyId := []byte{0x02, 0x03}
	message := ObliviousDNSMessage{
		MessageType:      0xFF,
		KeyID:            testKeyId,
		EncryptedMessage: nil,
	}

	serializedMessage := message.Marshal()
	expectedBytes := []byte{0xFF}
	expectedBytes = append(expectedBytes, []byte{0x00, 0x02}...) // non-empty key ID
	expectedBytes = append(expectedBytes, testKeyId...)
	expectedBytes = append(expectedBytes, []byte{0x00, 0x00}...) // empty message
	if !bytes.Equal(serializedMessage, expectedBytes) {
		t.Fatalf("Marshalling mismatch in the encoding. Got %x, received %x", serializedMessage, expectedBytes)
	}
}

func TestObliviousMessageMarshalNonEmptyKeyId(t *testing.T) {
	testMessage := []byte{0x06, 0x07, 0x08, 0x09}
	testKeyId := []byte{0x02, 0x03}
	message := ObliviousDNSMessage{
		MessageType:      0xFF,
		KeyID:            testKeyId,
		EncryptedMessage: testMessage,
	}

	serializedMessage := message.Marshal()
	expectedBytes := []byte{0xFF}
	expectedBytes = append(expectedBytes, []byte{0x00, 0x02}...) // non-empty key ID
	expectedBytes = append(expectedBytes, testKeyId...)
	expectedBytes = append(expectedBytes, []byte{0x00, 0x04}...) // non-empty message
	expectedBytes = append(expectedBytes, testMessage...)
	if !bytes.Equal(serializedMessage, expectedBytes) {
		t.Fatalf("Marshalling mismatch in the encoding. Got %x, received %x", serializedMessage, expectedBytes)
	}
}

func TestObliviousDoHQueryNoPaddingMarshal(t *testing.T) {
	dnsMessage := []byte{0x06, 0x07, 0x08, 0x09}
	query := CreateObliviousDNSQuery(dnsMessage, 0)

	serializedMessage := query.Marshal()
	expectedBytes := []byte{
		0x00, 0x04,
		0x06, 0x07, 0x08, 0x09,
		0x00, 0x00}
	if !bytes.Equal(serializedMessage, expectedBytes) {
		t.Fatalf("Marshalling mismatch in the encoding.")
	}
}

func TestObliviousDoHQueryPaddingMarshal(t *testing.T) {
	dnsMessage := []byte{0x06, 0x07, 0x08, 0x09}

	paddingLength := uint16(8)
	paddedBytes := make([]byte, paddingLength)
	query := CreateObliviousDNSQuery(dnsMessage, paddingLength)

	serializedMessage := query.Marshal()
	expectedBytes := []byte{
		0x00, 0x04,
		0x06, 0x07, 0x08, 0x09,
		0x00, uint8(paddingLength)}
	expectedBytes = append(expectedBytes, paddedBytes...)
	if !bytes.Equal(serializedMessage, expectedBytes) {
		t.Fatalf("Marshalling mismatch in the encoding.")
	}
}

func TestObliviousDoHMessage_Marshal(t *testing.T) {
	messageType := QueryType
	keyId := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	encryptedMessage := []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	odnsMessage := ObliviousDNSMessage{
		MessageType:      messageType,
		KeyID:            keyId,
		EncryptedMessage: encryptedMessage,
	}

	serializedMessage := odnsMessage.Marshal()
	expectedBytes := []byte{0x01,
		0x00, 0x05,
		0x00, 0x01, 0x02, 0x03, 0x04,
		0x00, 0x0B,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	if !bytes.Equal(serializedMessage, expectedBytes) {
		t.Fatalf("Failed to serialize correctly. Got %x, expected %x", serializedMessage, expectedBytes)
	}
}

func TestObliviousDoHMessage_Unmarshal(t *testing.T) {
	messageType := QueryType
	keyId := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	encryptedMessage := []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	odnsMessage := ObliviousDNSMessage{
		MessageType:      messageType,
		KeyID:            keyId,
		EncryptedMessage: encryptedMessage,
	}

	expectedBytes := []byte{0x01,
		0x00, 0x05,
		0x00, 0x01, 0x02, 0x03, 0x04,
		0x00, 0x0B,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	deserializedMessage, err := UnmarshalDNSMessage(expectedBytes)

	if err != nil {
		t.Fatalf("Failed to unmarshal ObliviousDNSMessage")
	}

	if !(deserializedMessage.MessageType == odnsMessage.MessageType) {
		t.Fatalf("Message type mismatch after unmarshaling")
	}

	if !bytes.Equal(deserializedMessage.KeyID, odnsMessage.KeyID) {
		t.Fatalf("Failed to unmarshal the KeyID correctly.")
	}

	if !bytes.Equal(deserializedMessage.EncryptedMessage, odnsMessage.EncryptedMessage) {
		t.Fatalf("Failed to unmarshal the Encrypted Message Correctly.")
	}
}
