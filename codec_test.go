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
