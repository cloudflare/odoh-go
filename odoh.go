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
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

const (
	ODOH_VERSION        = uint16(0xff03)
	ODOH_SECRET_LENGTH  = 32
	ODOH_PADDING_BYTE   = uint8(0)
	ODOH_LABEL_KEY_ID   = "odoh key id"
	ODOH_LABEL_KEY      = "odoh key"
	ODOH_LABEL_NONCE    = "odoh nonce"
	ODOH_LABEL_SECRET   = "odoh secret"
	ODOH_LABEL_QUERY    = "odoh query"
	ODOH_DEFAULT_KEMID  = uint16(0x20) // KEM is X25519 and HKDF with SHA256.
	ODOH_DEFAULT_KDFID  = uint16(0x01) // KDF is HKDF with SHA256.
	ODOH_DEFAULT_AEADID = uint16(0x01) // AEAD is AES-128 GCM authenticated cipher.
)

type ObliviousDoHConfigContents struct {
	KemID          uint16
	KdfID          uint16
	AeadID         uint16
	PublicKeyBytes []byte
}

func CreateObliviousDoHConfigContents(kemID uint16, kdfID uint16, aeadID uint16, publicKeyBytes []byte) (ObliviousDoHConfigContents, error) {
	_, kemScheme, err := getSuite(kemID, kdfID, aeadID)
	if err != nil {
		return ObliviousDoHConfigContents{}, err
	}

	_, err = kemScheme.UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return ObliviousDoHConfigContents{}, err
	}

	return ObliviousDoHConfigContents{
		KemID:          kemID,
		KdfID:          kdfID,
		AeadID:         aeadID,
		PublicKeyBytes: publicKeyBytes,
	}, nil
}

func (k ObliviousDoHConfigContents) KeyID() []byte {
	identifiers := make([]byte, 8)
	binary.BigEndian.PutUint16(identifiers[0:], k.KemID)
	binary.BigEndian.PutUint16(identifiers[2:], k.KdfID)
	binary.BigEndian.PutUint16(identifiers[4:], k.AeadID)
	binary.BigEndian.PutUint16(identifiers[6:], uint16(len(k.PublicKeyBytes)))
	config := append(identifiers, k.PublicKeyBytes...)

	KdfID := hpke.KDF(k.KdfID)
	prk := KdfID.Extract(config, nil)
	identifier := KdfID.Expand(prk, []byte(ODOH_LABEL_KEY_ID), uint(KdfID.ExtractSize()))
	return identifier
}

func (k ObliviousDoHConfigContents) Marshal() []byte {
	identifiers := make([]byte, 8)
	binary.BigEndian.PutUint16(identifiers[0:], k.KemID)
	binary.BigEndian.PutUint16(identifiers[2:], k.KdfID)
	binary.BigEndian.PutUint16(identifiers[4:], k.AeadID)
	binary.BigEndian.PutUint16(identifiers[6:], uint16(len(k.PublicKeyBytes)))

	response := append(identifiers, k.PublicKeyBytes...)
	return response
}

func UnmarshalObliviousDoHConfigContents(buffer []byte) (ObliviousDoHConfigContents, error) {
	if len(buffer) < 8 {
		return ObliviousDoHConfigContents{}, errors.New("Invalid serialized ObliviousDoHConfigContents")
	}

	kemID := binary.BigEndian.Uint16(buffer[0:])
	kdfID := binary.BigEndian.Uint16(buffer[2:])
	aeadID := binary.BigEndian.Uint16(buffer[4:])

	publicKeyLength := binary.BigEndian.Uint16(buffer[6:])

	if len(buffer[8:]) < int(publicKeyLength) {
		return ObliviousDoHConfigContents{}, errors.New("Invalid serialized ObliviousDoHConfigContents")
	}

	publicKeyBytes := buffer[8 : 8+publicKeyLength]

	return CreateObliviousDoHConfigContents(kemID, kdfID, aeadID, publicKeyBytes)
}

func (k ObliviousDoHConfigContents) PublicKey() []byte {
	return k.PublicKeyBytes
}

func (k ObliviousDoHConfigContents) CipherSuite() hpke.Suite {
	return hpke.NewSuite(hpke.KEM(k.KemID), hpke.KDF(k.KdfID), hpke.AEAD(k.AeadID))
}

type ObliviousDoHConfig struct {
	Version  uint16
	Contents ObliviousDoHConfigContents
}

func CreateObliviousDoHConfig(contents ObliviousDoHConfigContents) ObliviousDoHConfig {
	return ObliviousDoHConfig{
		Version:  ODOH_VERSION,
		Contents: contents,
	}
}

func (c ObliviousDoHConfig) Marshal() []byte {
	marshalledConfig := c.Contents.Marshal()

	buffer := make([]byte, 4)
	binary.BigEndian.PutUint16(buffer[0:], uint16(c.Version))
	binary.BigEndian.PutUint16(buffer[2:], uint16(len(marshalledConfig)))

	configBytes := append(buffer, marshalledConfig...)
	return configBytes
}

func parseConfigHeader(buffer []byte) (uint16, uint16, error) {
	if len(buffer) < 4 {
		return uint16(0), uint16(0), errors.New("Invalid ObliviousDoHConfig encoding")
	}

	version := binary.BigEndian.Uint16(buffer[0:])
	length := binary.BigEndian.Uint16(buffer[2:])
	return version, length, nil
}

func isSupportedConfigVersion(version uint16) bool {
	return version == ODOH_VERSION
}

func UnmarshalObliviousDoHConfig(buffer []byte) (ObliviousDoHConfig, error) {
	version, length, err := parseConfigHeader(buffer)
	if err != nil {
		return ObliviousDoHConfig{}, err
	}

	if !isSupportedConfigVersion(version) {
		return ObliviousDoHConfig{}, errors.New(fmt.Sprintf("Unsupported version: %04x", version))
	}
	if len(buffer[4:]) < int(length) {
		return ObliviousDoHConfig{}, errors.New(fmt.Sprintf("Invalid serialized ObliviousDoHConfig, expected %v bytes, got %v", length, len(buffer[4:])))
	}

	configContents, err := UnmarshalObliviousDoHConfigContents(buffer[4:])
	if err != nil {
		return ObliviousDoHConfig{}, err
	}

	return ObliviousDoHConfig{
		Version:  version,
		Contents: configContents,
	}, nil
}

type ObliviousDoHConfigs struct {
	Configs []ObliviousDoHConfig
}

func CreateObliviousDoHConfigs(configs []ObliviousDoHConfig) ObliviousDoHConfigs {
	return ObliviousDoHConfigs{
		Configs: configs,
	}
}

func (c ObliviousDoHConfigs) Marshal() []byte {
	serializedConfigs := make([]byte, 0)
	for _, config := range c.Configs {
		serializedConfigs = append(serializedConfigs, config.Marshal()...)
	}

	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer[0:], uint16(len(serializedConfigs)))

	result := append(buffer, serializedConfigs...)
	return result
}

func UnmarshalObliviousDoHConfigs(buffer []byte) (ObliviousDoHConfigs, error) {
	if len(buffer) < 2 {
		return ObliviousDoHConfigs{}, errors.New("Invalid ObliviousDoHConfigs encoding")
	}

	configs := make([]ObliviousDoHConfig, 0)
	length := binary.BigEndian.Uint16(buffer[0:])
	offset := uint16(2)

	for {
		configVersion, configLength, err := parseConfigHeader(buffer[offset:])
		if err != nil {
			return ObliviousDoHConfigs{}, errors.New("Invalid ObliviousDoHConfigs encoding")
		}

		if uint16(len(buffer[offset:])) < configLength {
			// The configs vector is encoded incorrectly, so discard the whole thing
			return ObliviousDoHConfigs{}, errors.New(fmt.Sprintf("Invalid serialized ObliviousDoHConfig, expected %v bytes, got %v", length, len(buffer[offset:])))
		}

		if isSupportedConfigVersion(configVersion) {
			config, err := UnmarshalObliviousDoHConfig(buffer[offset:])
			if err == nil {
				configs = append(configs, config)
			}
		} else {
			// Skip over unsupported versions
		}

		offset += 4 + configLength
		if offset >= 2+length {
			// Stop reading
			break
		}
	}

	return CreateObliviousDoHConfigs(configs), nil
}

type ObliviousDoHKeyPair struct {
	Config    ObliviousDoHConfig
	secretKey kem.PrivateKey
	Seed      []byte
}

func CreateKeyPairFromSeed(kemID uint16, kdfID uint16, aeadID uint16, ikm []byte) (ObliviousDoHKeyPair, error) {
	_, kemScheme, err := getSuite(kemID, kdfID, aeadID)
	if err != nil {
		return ObliviousDoHKeyPair{}, err
	}
	pk, sk := kemScheme.DeriveKeyPair(ikm)

	publicKeyBytes, err := pk.MarshalBinary()
	if err != nil {
		return ObliviousDoHKeyPair{}, err
	}
	configContents, err := CreateObliviousDoHConfigContents(kemID, kdfID, aeadID, publicKeyBytes)
	if err != nil {
		return ObliviousDoHKeyPair{}, err
	}

	config := CreateObliviousDoHConfig(configContents)

	return ObliviousDoHKeyPair{
		Config:    config,
		secretKey: sk,
		Seed:      ikm,
	}, nil
}

func CreateDefaultKeyPairFromSeed(seed []byte) (ObliviousDoHKeyPair, error) {
	return CreateKeyPairFromSeed(ODOH_DEFAULT_KEMID, ODOH_DEFAULT_KDFID, ODOH_DEFAULT_AEADID, seed)
}

func CreateKeyPair(kemID uint16, kdfID uint16, aeadID uint16) (ObliviousDoHKeyPair, error) {
	_, kemScheme, err := getSuite(kemID, kdfID, aeadID)
	if err != nil {
		return ObliviousDoHKeyPair{}, err
	}
	ikm := make([]byte, kemScheme.SeedSize())
	rand.Reader.Read(ikm)
	pk, sk := kemScheme.DeriveKeyPair(ikm)

	publicKeyBytes, err := pk.MarshalBinary()
	if err != nil {
		return ObliviousDoHKeyPair{}, err
	}
	configContents, err := CreateObliviousDoHConfigContents(kemID, kdfID, aeadID, publicKeyBytes)
	if err != nil {
		return ObliviousDoHKeyPair{}, err
	}

	config := CreateObliviousDoHConfig(configContents)

	return ObliviousDoHKeyPair{
		Config:    config,
		secretKey: sk,
		Seed:      ikm,
	}, nil
}

func CreateDefaultKeyPair() (ObliviousDoHKeyPair, error) {
	return CreateKeyPair(ODOH_DEFAULT_KEMID, ODOH_DEFAULT_KDFID, ODOH_DEFAULT_AEADID)
}

type QueryContext struct {
	odohSecret []byte
	suite      hpke.Suite
	query      []byte
	publicKey  ObliviousDoHConfigContents
}

func (c QueryContext) DecryptResponse(message ObliviousDNSMessage) ([]byte, error) {
	aad := append([]byte{byte(ResponseType)}, []byte{0x00, 0x00}...) // 0-length encoded KeyID

	_, kdfID, aeadID := c.suite.Params()
	odohPRK := kdfID.Extract(c.odohSecret, c.query)
	key := kdfID.Expand(odohPRK, []byte(ODOH_LABEL_KEY), aeadID.KeySize())

	aead, err := aeadID.New(key)
	if err != nil {
		return nil, err
	}
	nonce := kdfID.Expand(odohPRK, []byte(ODOH_LABEL_NONCE), uint(aead.NonceSize()))

	return aead.Open(nil, nonce, message.EncryptedMessage, aad)
}

type ResponseContext struct {
	query      []byte
	suite      hpke.Suite
	odohSecret []byte
}

func (c ResponseContext) EncryptResponse(response *ObliviousDNSResponse) (ObliviousDNSMessage, error) {
	aad := append([]byte{byte(ResponseType)}, []byte{0x00, 0x00}...) // 0-length encoded KeyID

	_, kdfID, aeadID := c.suite.Params()
	odohPRK := kdfID.Extract(c.odohSecret, c.query)
	key := kdfID.Expand(odohPRK, []byte(ODOH_LABEL_KEY), aeadID.KeySize())

	aead, err := aeadID.New(key)
	if err != nil {
		return ObliviousDNSMessage{}, err
	}

	nonce := kdfID.Expand(odohPRK, []byte(ODOH_LABEL_NONCE), uint(aead.NonceSize()))

	ciphertext := aead.Seal(nil, nonce, response.Marshal(), aad)

	odohMessage := ObliviousDNSMessage{
		KeyID:            nil,
		MessageType:      ResponseType,
		EncryptedMessage: ciphertext,
	}

	return odohMessage, nil
}

func (targetKey ObliviousDoHConfigContents) EncryptQuery(query *ObliviousDNSQuery) (ObliviousDNSMessage, QueryContext, error) {
	suite, kemScheme, err := getSuite(targetKey.KemID, targetKey.KdfID, targetKey.AeadID)
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}
	pkR, err := kemScheme.UnmarshalBinaryPublicKey(targetKey.PublicKeyBytes)
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}

	sender, err := suite.NewSender(pkR, []byte(ODOH_LABEL_QUERY))
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}

	keyID := targetKey.KeyID()
	keyIDLength := make([]byte, 2)
	binary.BigEndian.PutUint16(keyIDLength, uint16(len(keyID)))
	aad := append([]byte{byte(QueryType)}, keyIDLength...)
	aad = append(aad, keyID...)

	encodedMessage := query.Marshal()
	ct, err := sealer.Seal(encodedMessage, aad)
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}
	odohSecret := sealer.Export([]byte(ODOH_LABEL_SECRET), ODOH_SECRET_LENGTH)

	return ObliviousDNSMessage{
			KeyID:            targetKey.KeyID(),
			MessageType:      QueryType,
			EncryptedMessage: append(enc, ct...),
		}, QueryContext{
			odohSecret: odohSecret,
			suite:      *suite,
			query:      query.Marshal(),
			publicKey:  targetKey,
		}, nil
}

func validateMessagePadding(padding []byte) bool {
	validPadding := 1
	for _, v := range padding {
		validPadding &= subtle.ConstantTimeByteEq(v, ODOH_PADDING_BYTE)
	}
	return validPadding == 1
}

func (privateKey ObliviousDoHKeyPair) DecryptQuery(message ObliviousDNSMessage) (*ObliviousDNSQuery, ResponseContext, error) {
	if message.MessageType != QueryType {
		return nil, ResponseContext{}, errors.New("message is not a query")
	}

	suite, kemScheme, err := getSuite(
		privateKey.Config.Contents.KemID,
		privateKey.Config.Contents.KdfID,
		privateKey.Config.Contents.AeadID)
	if err != nil {
		return nil, ResponseContext{}, err
	}

	keySize := kemScheme.PublicKeySize()
	enc := message.EncryptedMessage[0:keySize]
	ct := message.EncryptedMessage[keySize:]

	receiver, err := suite.NewReceiver(privateKey.secretKey, []byte(ODOH_LABEL_QUERY))
	if err != nil {
		return nil, ResponseContext{}, err
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, ResponseContext{}, err
	}

	odohSecret := opener.Export([]byte(ODOH_LABEL_SECRET), ODOH_SECRET_LENGTH)

	keyID := privateKey.Config.Contents.KeyID()
	keyIDLength := make([]byte, 2)
	binary.BigEndian.PutUint16(keyIDLength, uint16(len(keyID)))
	aad := append([]byte{byte(QueryType)}, keyIDLength...)
	aad = append(aad, keyID...)

	dnsMessage, err := opener.Open(ct, aad)
	if err != nil {
		return nil, ResponseContext{}, err
	}

	query, err := UnmarshalQueryBody(dnsMessage)
	if err != nil {
		return nil, ResponseContext{}, err
	}

	if !validateMessagePadding(query.Padding) {
		return nil, ResponseContext{}, errors.New("invalid padding")
	}

	responseContext := ResponseContext{
		odohSecret: odohSecret,
		suite:      *suite,
		query:      query.Marshal(),
	}

	return query, responseContext, nil
}

func SealQuery(dnsQuery []byte, publicKey ObliviousDoHConfigContents) (ObliviousDNSMessage, QueryContext, error) {
	odohQuery := CreateObliviousDNSQuery(dnsQuery, 0)

	odohMessage, queryContext, err := publicKey.EncryptQuery(odohQuery)
	if err != nil {
		return ObliviousDNSMessage{}, QueryContext{}, err
	}

	return odohMessage, queryContext, nil
}

func (c QueryContext) OpenAnswer(message ObliviousDNSMessage) ([]byte, error) {
	if message.MessageType != ResponseType {
		return nil, errors.New("message is not a response")
	}

	decryptedResponseBytes, err := c.DecryptResponse(message)
	if err != nil {
		return nil, errors.New("unable to decrypt the obtained response using the symmetric key sent")
	}

	decryptedResponse, err := UnmarshalResponseBody(decryptedResponseBytes)
	if err != nil {
		return nil, err
	}

	return decryptedResponse.DnsMessage, nil
}

func getSuite(kemID uint16, kdfID uint16, aeadID uint16) (*hpke.Suite, kem.Scheme, error) {
	kem := hpke.KEM(kemID)
	if !kem.IsValid() {
		return nil, nil, errors.New("invalid KEM identifier")
	}
	kdf := hpke.KDF(kdfID)
	if !kdf.IsValid() {
		return nil, nil, errors.New("invalid KDF identifier")
	}
	aead := hpke.AEAD(aeadID)
	if !aead.IsValid() {
		return nil, nil, errors.New("invalid AEAD identifier")
	}

	suite := hpke.NewSuite(kem, kdf, aead)
	kemScheme := kem.Scheme()
	return &suite, kemScheme, nil
}
