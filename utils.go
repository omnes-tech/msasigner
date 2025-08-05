package msasigner

import (
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/omnes-tech/abi"
	"github.com/omnes-tech/msamisc/constants"
)

// wrapMessage wraps a message with Ethereum signed message header.
func wrapMessage(message []byte) []byte {
	return []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message))
}

// ParseDERSignature parses signature to DER format.
func ParseDERSignature(signature []byte) (r, s *big.Int, err error) {
	var parsedSig struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(signature, &parsedSig)
	if err != nil {
		return nil, nil, err
	}
	return parsedSig.R, parsedSig.S, nil
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type subjectPublicKeyInfo struct {
	Algorithm        algorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// ParseDERPublicKey parses public key from DER format.
func ParseDERPublicKey(pubKey []byte) (*big.Int, *big.Int, error) {

	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(pubKey, &spki); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal SubjectPublicKeyInfo: %v", err)
	}

	// The SubjectPublicKey field contains the uncompressed EC point (0x04 || X || Y)
	publicKeyBytes := spki.SubjectPublicKey.Bytes
	if len(publicKeyBytes) == 0 || publicKeyBytes[0] != 0x04 {
		return nil, nil, fmt.Errorf("unsupported key format")
	}

	// The length of X and Y coordinates for secp256r1 is 32 bytes each
	if len(publicKeyBytes) != 65 {
		return nil, nil, fmt.Errorf("unexpected public key length: %d", len(publicKeyBytes))
	}

	x := new(big.Int).SetBytes(publicKeyBytes[1 : 1+32])
	y := new(big.Int).SetBytes(publicKeyBytes[1+32:])

	return x, y, nil
}

func ToEthHash(message []byte) []byte {
	hashedMessage := crypto.Keccak256(message)
	wrappedMessage := wrapMessage(hashedMessage)
	return crypto.Keccak256(wrappedMessage)
}

func BuildEIP712Hash(message []byte, chainId *big.Int, address *common.Address, isHashed bool) ([]byte, []byte, error) {
	var messageHash []byte
	if isHashed {
		messageHash = message
	} else {
		wrappedMessage := wrapMessage(message)
		messageHash = crypto.Keccak256(wrappedMessage)
	}

	EIP1271Domain, err := abi.Encode(
		[]string{"bytes32", "bytes32"},
		constants.EIP1271_DOMAIN_TYPEHASH,
		messageHash,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode EIP1271 domain: %v", err)
	}
	EIP1271DomainHash := crypto.Keccak256(EIP1271Domain)

	EIP712DomainSeparator, err := abi.Encode(
		[]string{"bytes32", "bytes32", "bytes32", "uint256", "address"},
		constants.EIP712_DOMAIN_TYPEHASH,
		constants.EIP712_NAME_HASH,
		constants.EIP712_VERSION_HASH,
		chainId,
		address,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode EIP712 domain separator: %v", err)
	}
	EIP712DomainSeparatorHash := crypto.Keccak256(EIP712DomainSeparator)

	wrappedMessageEIP1271, err := abi.EncodePacked(
		[]string{"string", "bytes32", "bytes32"},
		"\x19\x01",
		EIP712DomainSeparatorHash,
		EIP1271DomainHash,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode wrapped message EIP1271: %v", err)
	}

	return crypto.Keccak256(wrappedMessageEIP1271), messageHash, nil
}
