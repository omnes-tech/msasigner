package msasigner

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/omnes-tech/msamisc/formatting"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// publicKeyInfo struct to unmarshal received PEM public key.
type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// GCPSigner important data used to request signature to KMS service.
type GCPSigner struct {
	KeyVersionName        string
	UncompressedPublicKey []byte
	BLSPublicKey          *bn254.G2Affine
	BLSPrivateKey         *big.Int
	EVMAddress            common.Address
	Client                *kms.KeyManagementClient
}

func NewGCPSigner(googleCredentials, googleProjectId, kmsLocationId, kmsKeyRingId, clientId, versionId string) (*GCPSigner, error) {
	credsJSON := []byte(googleCredentials)
	opt := option.WithCredentialsJSON(credsJSON)

	client, err := kms.NewKeyManagementClient(context.Background(), opt)
	if err != nil {
		return nil, fmt.Errorf("failed to create key management client (KMS): %v", err)
	}

	keyVersionName := buildKMSPath(
		googleProjectId,
		kmsLocationId,
		kmsKeyRingId,
		clientId,
		versionId,
	)
	req := &kmspb.GetPublicKeyRequest{
		Name: keyVersionName,
	}
	pubKey, err := client.GetPublicKey(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("unable to get public key (KMS): %v", err)
	}
	publicKey, err := convertToSecp256k1PublicKey([]byte(pubKey.Pem))
	if err != nil {
		return nil, fmt.Errorf("unable to convert PEM to SECP256K1 pubkey: %v", err)
	}

	uncompressedPublicKey := crypto.FromECDSAPub(publicKey.ToECDSA())
	evmAddress := common.BytesToAddress(crypto.Keccak256(uncompressedPublicKey[1:])[12:])

	return &GCPSigner{
		KeyVersionName:        keyVersionName,
		UncompressedPublicKey: uncompressedPublicKey,
		EVMAddress:            evmAddress,
		Client:                client,
	}, nil
}

func (k *GCPSigner) SignMessage(message []byte) (*big.Int, *big.Int, uint8, error) {

	wrappedMessage := wrapMessage(message)
	r, s, v, err := k.sign(wrappedMessage)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign message (KMS): %v", err)
	}

	return r, s, v, nil
}

func (k *GCPSigner) SignHashWithAddedV(message []byte) (*big.Int, *big.Int, uint8, error) {
	r, s, v, err := k.signHash(message, 27)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign hash (KMS): %v", err)
	}

	return r, s, v, nil
}

func (k *GCPSigner) SignHash(message []byte) (*big.Int, *big.Int, uint8, error) {
	r, s, v, err := k.signHash(message, 0)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign hash (KMS): %v", err)
	}

	return r, s, v, nil
}

func (k *GCPSigner) GetEVMAddress() *common.Address {
	return &k.EVMAddress
}

func (k *GCPSigner) ECRecover(message []byte, signature []byte, hashFunc func(...[]byte) []byte) (*common.Address, bool, error) {
	var hashedMessage []byte
	if hashFunc != nil {
		wrappedMessage := wrapMessage(message)
		hashedMessage = hashFunc(wrappedMessage)
	} else {
		hashedMessage = message
	}

	uncompressedPubKey, err := crypto.Ecrecover(hashedMessage, signature)
	if err != nil {
		return nil, false, fmt.Errorf("failed recover signature (KMS): %v", err)
	}
	recovered := common.BytesToAddress(crypto.Keccak256(uncompressedPubKey[1:])[12:])

	return &recovered, bytes.Equal(k.UncompressedPublicKey, uncompressedPubKey), nil
}

func (k *GCPSigner) ECRecoverRSV(message []byte, r, s *big.Int, v uint8, hashFunc func(...[]byte) []byte) (*common.Address, bool, error) {
	signature := formatting.JoinRSVSignature(r, s, v)
	return k.ECRecover(message, signature, hashFunc)
}

func (k *GCPSigner) GetPublicKey() string {
	return common.Bytes2Hex(k.UncompressedPublicKey)
}

func (k *GCPSigner) Delete() {
	defer k.Client.Close()
	k = nil
}

// sign signs message after hashing it.
func (k *GCPSigner) sign(message []byte) (*big.Int, *big.Int, uint8, error) {

	hashedMessage := crypto.Keccak256(message)
	return k.signHash(hashedMessage, 27)
}

// signHash signs given hash.
func (k *GCPSigner) signHash(hashedMessage []byte, addToV uint8) (*big.Int, *big.Int, uint8, error) {

	digestCRC32C := crc32c(hashedMessage)

	req := &kmspb.AsymmetricSignRequest{Name: k.KeyVersionName, Digest: &kmspb.Digest{
		Digest: &kmspb.Digest_Sha256{
			Sha256: hashedMessage,
		}}, DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C))}

	result, err := k.Client.AsymmetricSign(context.Background(), req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign digest: %v", err)
	}
	if !result.VerifiedDigestCrc32C {
		return nil, nil, 0, fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}
	if result.Name != req.Name {
		return nil, nil, 0, fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}
	if int64(crc32c(result.Signature)) != result.SignatureCrc32C.Value {
		return nil, nil, 0, fmt.Errorf("AsymmetricSign: response corrupted in-transit")
	}

	r, s, err := ParseDERSignature(result.Signature)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse DER signature: %v", err)
	}

	rs := common.LeftPadBytes(r.Bytes(), 32)
	rs = append(rs, common.LeftPadBytes(s.Bytes(), 32)...)
	for _, val := range []uint8{0, 1} {
		signature := append(rs, uint8(val))
		pubKey, err := crypto.Ecrecover(hashedMessage, signature)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to find the v param of signature: %v", err)
		}
		if bytes.Equal(pubKey, k.UncompressedPublicKey) {
			return r, s, val + addToV, nil
		}
	}

	return nil, nil, 0, fmt.Errorf("not a valid signature")
}

// crc32c used in the signature request process.
func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

// buildKMSPath builds path to find key.
func buildKMSPath(project, location, keyRing, cryptoKey, crypotKeyVersion string) string {
	return fmt.Sprintf(
		"projects/%v/locations/%v/keyRings/%v/cryptoKeys/%v/cryptoKeyVersions/%v",
		project,
		location,
		keyRing,
		cryptoKey,
		crypotKeyVersion,
	)
}

// convertToSecp256k1PublicKey converts PEM public key into SECP256K1 format.
func convertToSecp256k1PublicKey(pemPubKey []byte) (*secp256k1.PublicKey, error) {
	block, _ := pem.Decode(pemPubKey)
	if block == nil {
		return nil, errors.New("decoding public key PEM failed")
	}
	var pki publicKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &pki); err != nil {
		return nil, fmt.Errorf("unmarshalling public key PEM failed: %v", err)
	}
	pub, err := secp256k1.ParsePubKey(pki.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public key parsing failed: %v", err)
	}
	return pub, nil
}
