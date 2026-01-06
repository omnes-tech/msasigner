package msasigner

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/omnes-tech/abi"
)

type eip712Domain struct {
	Name              string          `json:"name"`
	Version           string          `json:"version"`
	ChainId           *big.Int        `json:"chainId"`
	VerifyingContract *common.Address `json:"verifyingContract"`
	Salt              []byte          `json:"salt"`
}

func NewEIP712Domain(name, version string, chainId *big.Int, verifyingContract *common.Address, salt []byte) (*eip712Domain, error) {
	if name == "" && version == "" && chainId == nil && verifyingContract == nil && salt == nil {
		return nil, fmt.Errorf("name, version, chainId, verifyingContract, and salt cannot all be empty")
	}
	if salt != nil && len(salt) != 32 {
		return nil, fmt.Errorf("salt must be 32 bytes")
	}

	return &eip712Domain{
		Name:              name,
		Version:           version,
		ChainId:           chainId,
		VerifyingContract: verifyingContract,
		Salt:              salt,
	}, nil
}

func (e *eip712Domain) DomainTypeHash() []byte {
	first := true
	domainString := "EIP712Domain("
	if e.Name != "" {
		if first {
			domainString += "string name"
			first = false
		} else {
			domainString += ",string name"
		}
	}
	if e.Version != "" {
		if first {
			domainString += "string version"
			first = false
		} else {
			domainString += ",string version"
		}
	}
	if e.ChainId != nil {
		if first {
			domainString += "uint256 chainId"
			first = false
		} else {
			domainString += ",uint256 chainId"
		}
	}
	if e.VerifyingContract != nil {
		if first {
			domainString += "address verifyingContract"
			first = false
		} else {
			domainString += ",address verifyingContract"
		}
	}
	if e.Salt != nil {
		if first {
			domainString += "bytes32 salt"
			first = false
		} else {
			domainString += ",bytes32 salt"
		}
	}
	domainString += ")"

	return crypto.Keccak256([]byte(domainString))
}

func (e *eip712Domain) DomainSeparator() ([]byte, error) {
	domainTypeHash := e.DomainTypeHash()

	values := []any{domainTypeHash}
	types := []string{"bytes32"}
	if e.Name != "" {
		hashedName := crypto.Keccak256([]byte(e.Name))
		values = append(values, hashedName)
		types = append(types, "bytes32")
	}
	if e.Version != "" {
		hashedVersion := crypto.Keccak256([]byte(e.Version))
		values = append(values, hashedVersion)
		types = append(types, "bytes32")
	}
	if e.ChainId != nil {
		values = append(values, e.ChainId)
		types = append(types, "uint256")
	}
	if e.VerifyingContract != nil {
		values = append(values, e.VerifyingContract)
		types = append(types, "address")
	}
	if e.Salt != nil {
		values = append(values, e.Salt)
		types = append(types, "bytes32")
	}

	encoded, err := abi.Encode(types, values...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode domain separator: %w", err)
	}

	return crypto.Keccak256(encoded), nil
}

type Data struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value any    `json:"value"`
}

func (e *eip712Domain) HashStruct(name string, data []Data) ([]byte, error) {
	structTypeString := name + "("
	values := []any{}
	types := []string{}
	for _, d := range data {
		structTypeString += fmt.Sprintf("%s %s,", d.Type, d.Name)

		if d.Type == "bytes" || d.Type == "string" {
			var value []byte
			if d.Type == "bytes" {
				value = crypto.Keccak256((d.Value.([]byte)))
			} else {
				value = crypto.Keccak256([]byte(d.Value.(string)))
			}
			values = append(values, value)
			types = append(types, "bytes32")
		} else {
			types = append(types, d.Type)
			values = append(values, d.Value)
		}
	}
	structTypeString = strings.TrimSuffix(structTypeString, ",") + ")"
	structTypeHash := crypto.Keccak256([]byte(structTypeString))
	values = append([]any{structTypeHash}, values...)

	encoded, err := abi.Encode(types, values...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode struct: %w", err)
	}
	return crypto.Keccak256(encoded), nil
}

func (e *eip712Domain) Message(name string, data []Data) ([]byte, error) {
	domainSeparator, err := e.DomainSeparator()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain separator: %w", err)
	}
	hashStruct, err := e.HashStruct(name, data)
	if err != nil {
		return nil, fmt.Errorf("failed to hash struct: %w", err)
	}

	encoded, err := abi.EncodePacked([]string{"bytes2", "bytes32", "bytes32"}, []byte{0x19, 0x01}, domainSeparator, hashStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to encode packed: %w", err)
	}
	return encoded, nil
}

func (e *eip712Domain) Digest(name string, data []Data) ([]byte, error) {
	message, err := e.Message(name, data)
	if err != nil {
		return nil, fmt.Errorf("failed to get message: %w", err)
	}
	return crypto.Keccak256(message), nil
}
