package msasigner

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/websocket"
	"github.com/omnes-tech/abi"
	"github.com/omnes-tech/msamisc/codec"
)

// PasskeyWebSocketMessage represents the message structure for WebSocket communication
type PasskeyWebSocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// PasskeyAuthRequest represents the authentication request sent via WebSocket
type PasskeyAuthRequest struct {
	Hash string `json:"hash"`
}

// PasskeyAuthResponse represents the authentication response received via WebSocket
type PasskeyAuthResponse struct {
	AuthenticatorData string `json:"authenticatorData"` // base64url string
	ClientDataJSON    string `json:"clientDataJSON"`    // stringified JSON
	Signature         []byte `json:"signature"`         // bytes array of DER signature
}

type PasskeySigner struct {
	WebSocketURL string
}

// NewPasskeySigner creates a new PasskeySigner instance.
func NewPasskeySigner(wsUrl string) (*PasskeySigner, error) {
	return &PasskeySigner{
		WebSocketURL: wsUrl,
	}, nil
}

// SignMessage signs a message using WebSocket-based passkey authentication
func (k *PasskeySigner) SignMessage(message []byte) ([]byte, error) {
	signature, err := k.sign(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message (KMS): %v", err)
	}

	return signature, nil
}

// SignHash signs a hash using WebSocket-based passkey authentication
func (k *PasskeySigner) SignHash(message []byte) ([]byte, error) {
	signature, err := k.signHash(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash (KMS): %v", err)
	}

	return signature, nil
}

// SignTx signs a transaction using WebSocket-based passkey authentication
func (k *PasskeySigner) SignTx(message []byte) ([]byte, error) {
	return k.SignHash(message)
}

// Delete deletes the PasskeySigner instance
func (k *PasskeySigner) Delete() {
	k = nil
}

// sign signs message after hashing it.
func (k *PasskeySigner) sign(message []byte) ([]byte, error) {

	hashedMessage := crypto.Keccak256(message)
	return k.signHash(hashedMessage)
}

// signHash signs given hash.
func (k *PasskeySigner) signHash(hashedMessage []byte) ([]byte, error) {
	if k.WebSocketURL == "" {
		return nil, fmt.Errorf("WebSocket URL not configured")
	}

	hashHex := common.Bytes2Hex(hashedMessage)

	// Connect to WebSocket
	u, err := url.Parse(k.WebSocketURL)
	if err != nil {
		return nil, fmt.Errorf("invalid WebSocket URL: %v", err)
	}

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to WebSocket: %v", err)
	}
	defer conn.Close()

	// Send authentication request
	authRequest := PasskeyWebSocketMessage{
		Type: "auth_request",
		Data: PasskeyAuthRequest{
			Hash: hashHex,
		},
	}

	err = conn.WriteJSON(authRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to send authentication request: %v", err)
	}

	// Wait for response with timeout
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	var response PasskeyWebSocketMessage
	err = conn.ReadJSON(&response)
	if err != nil {
		return nil, fmt.Errorf("failed to read authentication response: %v", err)
	}

	if response.Type != "auth_response" {
		return nil, fmt.Errorf("unexpected response type: %s", response.Type)
	}

	// Parse the response data
	responseData, err := json.Marshal(response.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %v", err)
	}

	var authResponse PasskeyAuthResponse
	err = json.Unmarshal(responseData, &authResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal authentication response: %v", err)
	}

	// Validate the response
	if authResponse.AuthenticatorData == "" {
		return nil, fmt.Errorf("missing authenticator data in response")
	}
	if authResponse.ClientDataJSON == "" {
		return nil, fmt.Errorf("missing client data JSON in response")
	}
	if len(authResponse.Signature) == 0 {
		return nil, fmt.Errorf("missing signature in response")
	}

	r, s, err := parseDERSignature(authResponse.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER signature: %v", err)
	}

	authenticatorDataHex, err := codec.DecodeBase64ToHex(authResponse.AuthenticatorData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode authenticator data: %v", err)
	}

	encodedSig, err := abi.Encode(
		[]string{"(bytes,string,uint256,uint256,uint256,uint256)"},
		[]any{
			common.Hex2Bytes(authenticatorDataHex),
			authResponse.ClientDataJSON,
			big.NewInt(23),
			big.NewInt(1),
			r,
			s,
		})
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	return encodedSig, nil
}

func parseDERSignature(signature []byte) (*big.Int, *big.Int, error) {
	// Parse DER signature to extract r and s
	// This is a simplified DER parsing for ECDSA signatures
	rStart := 4 // Skip DER header
	rLength := int(signature[rStart-1])
	r := signature[rStart : rStart+rLength]

	// Remove leading zero if present (for positive numbers)
	if r[0] == 0 {
		r = r[1:]
	}

	sStart := rStart + rLength + 2 // Skip to s component
	sLength := int(signature[sStart-1])
	s := signature[sStart : sStart+sLength]

	// Remove leading zero if present (for positive numbers)
	if s[0] == 0 {
		s = s[1:]
	}

	// Convert to big.Int strings
	rBigInt := big.NewInt(0).SetBytes(r)
	sBigInt := big.NewInt(0).SetBytes(s)

	return rBigInt, sBigInt, nil
}
