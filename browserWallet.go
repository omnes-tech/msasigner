package msasigner

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/websocket"
	"github.com/omnes-tech/msamisc/formatting"
)

// PasskeyWebSocketMessage represents the message structure for WebSocket communication
type BrowserWalletWebSocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// PasskeyAuthRequest represents the authentication request sent via WebSocket
type BrowserWalletAuthRequest struct {
	Hash string `json:"hash"`
}

// PasskeyAuthResponse represents the authentication response received via WebSocket
type BrowserWalletAuthResponse struct {
	R   *big.Int `json:"r"`
	S   *big.Int `json:"s"`
	V   uint8    `json:"v"`
	Raw []byte   `json:"raw"` // bytes array of DER signature
}

type BrowserWalletSigner struct {
	WebSocketURL string
	PublicKey    *ecdsa.PublicKey
	EVMAddress   common.Address
}

// NewPKSigner creates a new PKSigner instance from a hex-encoded private key.
// It converts the hex string to an ECDSA private key and derives the public key and
// EVM address from it.
// Returns an error if the conversion fails.
func NewBrowserWalletSigner(wsUrl string, publicKey []byte) (*BrowserWalletSigner, error) {

	publicKeyECDSA, err := crypto.UnmarshalPubkey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to ECDSA: %v", err)
	}
	evmAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	return &BrowserWalletSigner{
		WebSocketURL: wsUrl,
		PublicKey:    publicKeyECDSA,
		EVMAddress:   evmAddress,
	}, nil
}

func (k *BrowserWalletSigner) SignMessage(message []byte) ([]byte, error) {

	wrappedMessage := formatting.WrapMessage(message)
	r, s, v, err := k.sign(wrappedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message (KMS): %v", err)
	}

	return formatting.JoinRSVSignature(r, s, v), nil
}

func (k *BrowserWalletSigner) SignHashWithAddedV(message []byte) ([]byte, error) {
	r, s, v, err := k.signHash(message, 27)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash (KMS): %v", err)
	}

	return formatting.JoinRSVSignature(r, s, v), nil
}

func (k *BrowserWalletSigner) SignHash(message []byte) ([]byte, error) {
	r, s, v, err := k.signHash(message, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash (KMS): %v", err)
	}

	return formatting.JoinRSVSignature(r, s, v), nil
}

func (k *BrowserWalletSigner) SignTx(message []byte) ([]byte, error) {
	return k.SignHash(message)
}

func (k *BrowserWalletSigner) GetEVMAddress() *common.Address {
	return &k.EVMAddress
}

func (k *BrowserWalletSigner) ECRecover(message []byte, signature []byte, hashFunc func(...[]byte) []byte) (*common.Address, bool, error) {
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

func (k *BrowserWalletSigner) ECRecoverRSV(message []byte, r, s *big.Int, v uint8, hashFunc func(...[]byte) []byte) (*common.Address, bool, error) {
	signature := formatting.JoinRSVSignature(r, s, v)
	return k.ECRecover(message, signature, hashFunc)
}

func (k *BrowserWalletSigner) GetPublicKey() string {
	return common.Bytes2Hex(crypto.FromECDSAPub(k.PublicKey))
}

func (k *BrowserWalletSigner) Delete() {
	k = nil
}

// sign signs message after hashing it.
func (k *BrowserWalletSigner) sign(message []byte) (*big.Int, *big.Int, uint8, error) {

	hashedMessage := crypto.Keccak256(message)
	return k.signHash(hashedMessage, 27)
}

// signHash signs given hash.
func (k *BrowserWalletSigner) signHash(hashedMessage []byte, addToV uint8) (*big.Int, *big.Int, uint8, error) {

	if k.WebSocketURL == "" {
		return nil, nil, 0, fmt.Errorf("WebSocket URL not configured")
	}

	hashHex := common.Bytes2Hex(hashedMessage)

	// Connect to WebSocket
	u, err := url.Parse(k.WebSocketURL)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("invalid WebSocket URL: %v", err)
	}

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to connect to WebSocket: %v", err)
	}
	defer conn.Close()

	// Send authentication request
	authRequest := BrowserWalletWebSocketMessage{
		Type: "auth_request",
		Data: BrowserWalletAuthRequest{
			Hash: hashHex,
		},
	}

	err = conn.WriteJSON(authRequest)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to send authentication request: %v", err)
	}

	// Wait for response with timeout
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	var response BrowserWalletWebSocketMessage
	err = conn.ReadJSON(&response)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to read authentication response: %v", err)
	}

	if response.Type != "auth_response" {
		return nil, nil, 0, fmt.Errorf("unexpected response type: %s", response.Type)
	}

	// Parse the response data
	responseData, err := json.Marshal(response.Data)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to marshal response data: %v", err)
	}

	var authResponse BrowserWalletAuthResponse
	err = json.Unmarshal(responseData, &authResponse)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to unmarshal authentication response: %v", err)
	}

	// Validate the response
	if authResponse.R == nil {
		return nil, nil, 0, fmt.Errorf("missing r in response")
	}
	if authResponse.S == nil {
		return nil, nil, 0, fmt.Errorf("missing s in response")
	}

	return authResponse.R, authResponse.S, authResponse.V + addToV, nil
}
