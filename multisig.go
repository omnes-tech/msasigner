package msasigner

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/omnes-tech/msamisc/types"
)

type MultisigSigner struct {
	signers []types.Signer
}

func NewMultisigSigner(signers []types.Signer) *MultisigSigner {
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

func (m *MultisigSigner) GetEVMAddress(index int) *common.Address {
	return m.signers[index].GetEVMAddress()
}

func (m *MultisigSigner) GetEVMAddresses() []*common.Address {
	addresses := make([]*common.Address, len(m.signers))
	for i, signer := range m.signers {
		addresses[i] = signer.GetEVMAddress()
	}

	return addresses
}
