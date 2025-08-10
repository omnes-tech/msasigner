package msasigner

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/omnes-tech/msamisc/formatting"
	"github.com/omnes-tech/msasigner/fireblocks"
)

const BASE_URL = "https://api.fireblocks.io"

// FireblocksSigner struct with all required fields to request signing.
type FireblocksSigner struct {
	VaultId               string
	AssetId               string
	UncompressedPublicKey []byte
	BLSPublicKey          *bn254.G2Affine
	BLSPrivateKey         *big.Int
	EVMAddress            common.Address
	FireblocksSdk         *fireblocks.FireblocksSDK
}

func NewFireblocksSigner(apiPrivateKey []byte, apiKey string, clientId, assetId string) (*FireblocksSigner, error) {
	fireblocksSdk, err := fireblocks.NewInstance(
		apiPrivateKey,
		apiKey,
		BASE_URL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Fireblocks SDK instance: %v", err)
	}

	vaultId, err := fireblocksSdk.GetVaultId(clientId)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault accounts: %v", err)
	}

	evmAddress, err := fireblocksSdk.GetAddress(vaultId, assetId)
	if err != nil {
		return nil, fmt.Errorf("failed to get account address: %v", err)
	}

	return &FireblocksSigner{
		VaultId:       vaultId,
		AssetId:       assetId,
		EVMAddress:    *evmAddress,
		FireblocksSdk: fireblocksSdk,
	}, nil
}

func (m *FireblocksSigner) SignMessage(message []byte) (*big.Int, *big.Int, uint8, error) {

	wrappedMessage := formatting.WrapMessage(message)

	r, s, v, err := m.sign(wrappedMessage)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign message (MPC): %v", err)
	}

	return r, s, v, nil
}

func (k *FireblocksSigner) SignHashWithAddedV(message []byte) (*big.Int, *big.Int, uint8, error) {
	r, s, v, err := k.signHash(message, 27)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign hash (KMS): %v", err)
	}

	return r, s, v, nil
}

func (m *FireblocksSigner) SignHash(message []byte) (*big.Int, *big.Int, uint8, error) {
	r, s, v, err := m.signHash(message, 0)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign hash (MPC): %v", err)
	}

	return r, s, v, nil
}

func (m *FireblocksSigner) SignTx(message []byte) (*big.Int, *big.Int, uint8, error) {
	return m.SignHash(message)
}

func (m *FireblocksSigner) GetEVMAddress() *common.Address {
	return &m.EVMAddress
}
func (m *FireblocksSigner) ECRecover(message []byte, signature []byte, hashFunc func(...[]byte) []byte) (*common.Address, bool, error) {
	var hashedMessage []byte
	if hashFunc != nil {
		wrappedMessage := formatting.WrapMessage(message)
		hashedMessage = hashFunc(wrappedMessage)
	} else {
		hashedMessage = message
	}

	uncompressedPubKey, err := crypto.Ecrecover(hashedMessage, signature)
	if err != nil {
		return nil, false, fmt.Errorf("failed recover signature (MPC): %v", err)
	}
	recovered := common.BytesToAddress(crypto.Keccak256(uncompressedPubKey[1:])[12:])

	return &recovered, bytes.Equal(m.UncompressedPublicKey, uncompressedPubKey), nil
}
func (m *FireblocksSigner) ECRecoverRSV(message []byte, r, s *big.Int, v uint8, hashFunc func(...[]byte) []byte) (*common.Address, bool, error) {

	signature := formatting.JoinRSVSignature(r, s, v)
	return m.ECRecover(message, signature, hashFunc)
}

func (m *FireblocksSigner) GetPublicKey() string {
	return common.Bytes2Hex(m.UncompressedPublicKey)
}

func (m *FireblocksSigner) Delete() {
}

func (m *FireblocksSigner) sign(message []byte) (*big.Int, *big.Int, uint8, error) {

	hashedMessage := crypto.Keccak256(message)
	return m.signHash(hashedMessage, 27)
}

func (m *FireblocksSigner) signHash(hashedMessage []byte, addToV uint8) (*big.Int, *big.Int, uint8, error) {

	pubKey, r, s, v, err := m.FireblocksSdk.Sign(hashedMessage, m.VaultId, m.AssetId)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to sign message (Fireblocks): %v", err)
	}

	if len(m.UncompressedPublicKey) == 0 {
		compressedPubKeyBytes, err := hex.DecodeString(pubKey)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode hex string: %v", err)
		} else {
			uPubKey, err := crypto.DecompressPubkey(compressedPubKeyBytes)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to decompress public key: %v", err)
			}

			xPadded := common.LeftPadBytes(uPubKey.X.Bytes(), 32)
			yPadded := common.LeftPadBytes(uPubKey.Y.Bytes(), 32)
			uncompressedPubKeyBytes := append(xPadded, yPadded...)
			uncompressedPubKeyBytes = append([]byte{0x04}, uncompressedPubKeyBytes...)
			m.UncompressedPublicKey = uncompressedPubKeyBytes
		}
	}

	return r, s, v + addToV, nil
}
