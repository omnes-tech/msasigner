package msasigner

import (
	"github.com/ethereum/go-ethereum/common"
)

type Signer interface {
	SignMessage(message []byte) ([]byte, error)
	SignHash(message []byte) ([]byte, error)
	SignTx(message []byte) ([]byte, error)
	GetEVMAddress() (common.Address, error)
}

type MultisigSigner struct {
	signers []Signer
}

func NewMultisigSigner(signers []Signer) *MultisigSigner {
	return &MultisigSigner{signers: signers}
}

func (m *MultisigSigner) SignMessage(message []byte) ([]byte, error) {
	var signatures []byte
	for _, signer := range m.signers {
		signature, err := signer.SignMessage(message)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, signature...)
	}
	return signatures, nil
}

func (m *MultisigSigner) SignHash(message []byte) ([]byte, error) {
	var signatures []byte
	for _, signer := range m.signers {
		signature, err := signer.SignHash(message)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, signature...)
	}
	return signatures, nil
}

func (m *MultisigSigner) SignTx(message []byte) ([]byte, error) {
	var signatures []byte
	for _, signer := range m.signers {
		signature, err := signer.SignTx(message)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, signature...)
	}
	return signatures, nil
}

func (m *MultisigSigner) GetEVMAddress(index int) (common.Address, error) {
	return m.signers[index].GetEVMAddress()
}

func (m *MultisigSigner) GetEVMAddresses() ([]common.Address, error) {
	addresses := make([]common.Address, len(m.signers))
	for i, signer := range m.signers {
		address, err := signer.GetEVMAddress()
		if err != nil {
			return nil, err
		}
		addresses[i] = address
	}
	return addresses, nil
}
