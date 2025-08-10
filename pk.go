package msasigner

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/omnes-tech/msamisc/formatting"
)

type PKSigner struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	EVMAddress common.Address
}

// NewPKSigner creates a new PKSigner instance from a hex-encoded private key.
// It converts the hex string to an ECDSA private key and derives the public key and
// EVM address from it.
// Returns an error if the conversion fails.
func NewPKSigner(privateKeyHex string) (*PKSigner, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key to ECDSA: %v", err)
	}

	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	evmAddress := crypto.PubkeyToAddress(*publicKey)

	return &PKSigner{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		EVMAddress: evmAddress,
	}, nil
}

func (k *PKSigner) SignMessage(message []byte) (*big.Int, *big.Int, uint8, error) {

	wrappedMessage := formatting.WrapMessage(message)
	r, s, v, err := k.sign(wrappedMessage)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign message (KMS): %v", err)
	}

	return r, s, v, nil
}

func (k *PKSigner) SignHashWithAddedV(message []byte) (*big.Int, *big.Int, uint8, error) {
	r, s, v, err := k.signHash(message, 27)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign hash (KMS): %v", err)
	}

	return r, s, v, nil
}

func (k *PKSigner) SignHash(message []byte) (*big.Int, *big.Int, uint8, error) {
	r, s, v, err := k.signHash(message, 0)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign hash (KMS): %v", err)
	}

	return r, s, v, nil
}

func (k *PKSigner) SignTx(message []byte) (*big.Int, *big.Int, uint8, error) {
	return k.SignHash(message)
}

func (k *PKSigner) GetEVMAddress() *common.Address {
	return &k.EVMAddress
}

func (k *PKSigner) ECRecover(message []byte, signature []byte, hashFunc func(...[]byte) []byte) (*common.Address, bool, error) {
	var hashedMessage []byte
	if hashFunc != nil {
		wrappedMessage := formatting.WrapMessage(message)
		hashedMessage = hashFunc(wrappedMessage)
	} else {
		hashedMessage = message
	}

	uncompressedPubKeyOnData := crypto.FromECDSAPub(k.PublicKey)
	uncompressedPubKey, err := crypto.Ecrecover(hashedMessage, signature)
	if err != nil {
		return nil, false, fmt.Errorf("failed recover signature (KMS): %v", err)
	}
	recovered := common.BytesToAddress(crypto.Keccak256(uncompressedPubKey[1:])[12:])

	return &recovered, bytes.Equal(uncompressedPubKeyOnData, uncompressedPubKey), nil
}

func (k *PKSigner) ECRecoverRSV(message []byte, r, s *big.Int, v uint8, hashFunc func(...[]byte) []byte) (*common.Address, bool, error) {
	signature := formatting.JoinRSVSignature(r, s, v)
	return k.ECRecover(message, signature, hashFunc)
}

func (k *PKSigner) GetPublicKey() string {
	return common.Bytes2Hex(crypto.FromECDSAPub(k.PublicKey))
}

func (k *PKSigner) Delete() {
	k = nil
}

// sign signs message after hashing it.
func (k *PKSigner) sign(message []byte) (*big.Int, *big.Int, uint8, error) {

	hashedMessage := crypto.Keccak256(message)
	return k.signHash(hashedMessage, 27)
}

// signHash signs given hash.
func (k *PKSigner) signHash(hashedMessage []byte, addToV uint8) (*big.Int, *big.Int, uint8, error) {

	signature, err := crypto.Sign(hashedMessage, k.PrivateKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign hash (PK): %v", err)
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	v := signature[64]

	return r, s, v + addToV, nil
}
