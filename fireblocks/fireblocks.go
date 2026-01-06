// Package fireblocks provides a Go SDK for interacting with the Fireblocks API.
// It enables signing messages, managing vault accounts, and retrieving transaction details.
//
// Example usage:
//
//	sdk, err := fireblocks.NewInstance(privateKey, apiKey, apiURL)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	address, err := sdk.GetAddress(vaultId, assetId)
//	signature, r, s, v, err := sdk.Sign(hashedMessage, vaultId, assetId)
package fireblocks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt"
	"github.com/omnes-tech/msamisc/formatting"
)

type FireblocksSDK struct {
	apiBaseURL string
	kto        *FbKeyMgmt
}

// NewInstance - create new type to handle Fireblocks API requests
func NewInstance(pk []byte, ak string, url string) (*FireblocksSDK, error) {

	s := new(FireblocksSDK)
	s.apiBaseURL = url
	privateK, err := jwt.ParseRSAPrivateKeyFromPEM(pk)
	if err != nil {
		return nil, err
	}

	s.kto = NewInstanceKeyMgmt(privateK, ak)

	return s, nil
}

func (f *FireblocksSDK) GetVaultId(nameSuffix string) (string, error) {
	query := fmt.Sprintf("/v1/vault/accounts_paged?nameSuffix=%v&orderBy=DESC&limit=200", nameSuffix)

	token, err := f.kto.createAndSignJWTToken(query, "")
	if err != nil {
		return "", fmt.Errorf("error signing JWT token (Fireblocks): %v", err)
	}
	request, err := http.NewRequest("GET", f.apiBaseURL+query, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request to Fireblocks: %v", err)
	}

	request.Header.Add("X-API-Key", f.kto.apiKey)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))

	res, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("error during request to Fireblocks: %v", err)
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response from Fireblocks: %v", err)
	}

	var vaultAccounts VaultAccounts
	err = json.Unmarshal(body, &vaultAccounts)
	if err != nil {
		return "", err
	}

	var vaultId string
	if len(vaultAccounts.Accounts) > 0 {
		vaultId = vaultAccounts.Accounts[0].Id
	} else {
		return "", fmt.Errorf("no vault ID returned (Fireblocks)")
	}

	return vaultId, nil
}

func (f *FireblocksSDK) GetAddress(vaultId, assetId string) (*common.Address, error) {
	query := fmt.Sprintf("/v1/vault/accounts/%s/%s/addresses", vaultId, assetId)
	returnedData, err := f.getRequest(query)
	if err != nil {
		return nil, err
	}

	var assetAddresses []VaultAccountAssetAddress
	err = json.Unmarshal([]byte(returnedData), &assetAddresses)
	if err != nil {
		return nil, fmt.Errorf("error getting asset addresses (Fireblocks): %v", err)
	}

	var evmAddress common.Address
	if len(assetAddresses) > 0 {
		evmAddress = common.HexToAddress(assetAddresses[0].Address)
	} else {
		return nil, fmt.Errorf("no addresses returned (Fireblocks)")
	}

	return &evmAddress, nil
}

func (f *FireblocksSDK) Sign(hashedMessage []byte, vaultId, assetId string) (string, *big.Int, *big.Int, uint8, error) {

	payload := map[string]interface{}{
		"assetId": assetId,
		"source": DestinationTransferPeerPath{
			TPeerType: "VAULT_ACCOUNT",
			TPeerId:   vaultId,
		},
		"operation": "RAW",
		"extraParameters": ExtraParameters{
			RawMessageData: Messages{
				Messages: []RawMessageDataStruct{
					{
						Content: formatting.Remove0xPrefix(common.Bytes2Hex(hashedMessage)),
					},
				},
			},
		},
	}

	returnedData, err := f.postRequest("/v1/transactions", payload)
	if err != nil {
		return "", nil, nil, 0, err
	}

	var transactionResponse CreateTransactionResponse
	err = json.Unmarshal(returnedData, &transactionResponse)
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("failed to unmarshal transaction response from Fireblocks: %v", err)
	}
	if len(transactionResponse.Id) == 0 {
		return "", nil, nil, 0, fmt.Errorf("no ID returned from Fireblocks")
	}

	var tx TransactionDetails
	tx.Status = transactionResponse.Status
	trials := 0
	for trials == 0 ||
		(tx.Status != "COMPLETED" &&
			tx.Status != "CANCELLED" &&
			tx.Status != "REJECTED" &&
			tx.Status != "FAILED" &&
			tx.Status != "TIMEOUT" &&
			tx.Status != "BLOCKED" &&
			trials < FIREBLOCKS_TRIALS_LIMIT) {

		tx, err = f.GetTransactionById(transactionResponse.Id)
		if err != nil {
			return "", nil, nil, 0, fmt.Errorf("failed get transaction from Fireblocks: %v", err)
		}

		time.Sleep(FIREBLOCKS_SLEEP_TIME)
		trials += 1
	}

	if tx.Status != "COMPLETED" && trials == FIREBLOCKS_TRIALS_LIMIT {
		return "", nil, nil, 0, fmt.Errorf("trials limit reached (Fireblocks)")
	}
	if tx.Status != "COMPLETED" {
		return "", nil, nil, 0, fmt.Errorf("transaction status is NOT 'COMPLETED' (Fireblocks). Status: '%v'", tx.Status)
	}

	r, ok := new(big.Int).SetString(tx.SignedMessages[0].Signature.R, 16)
	if !ok {
		return "", nil, nil, 0, fmt.Errorf("failed to parse R from signature (Fireblocks)")
	}
	s, ok := new(big.Int).SetString(tx.SignedMessages[0].Signature.S, 16)
	if !ok {
		return "", nil, nil, 0, fmt.Errorf("failed to parse S from signature (Fireblocks)")
	}

	return tx.SignedMessages[0].PublicKey,
		r,
		s,
		tx.SignedMessages[0].Signature.V,
		nil
}

func (f *FireblocksSDK) GetTransactionById(txId string) (TransactionDetails, error) {

	query := fmt.Sprintf("/v1/transactions/%s", txId)
	returnedData, err := f.getRequest(query)
	if err != nil {
		return TransactionDetails{}, err
	}

	var transactionDetails TransactionDetails
	err = json.Unmarshal(returnedData, &transactionDetails)
	if err != nil {
		return TransactionDetails{}, err
	}

	return transactionDetails, nil
}

func (f *FireblocksSDK) getRequest(query string) ([]byte, error) {
	token, err := f.kto.createAndSignJWTToken(query, "")
	if err != nil {
		return nil, fmt.Errorf("error signing JWT token (Fireblocks): %v", err)
	}
	request, err := http.NewRequest("GET", f.apiBaseURL+query, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request to Fireblocks: %v", err)
	}

	request.Header.Add("X-API-Key", f.kto.apiKey)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))

	res, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("error during request to Fireblocks: %v", err)
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response from Fireblocks: %v", err)
	}

	return body, nil
}

func (f *FireblocksSDK) postRequest(path string, payload map[string]interface{}) ([]byte, error) {

	var stringPayload string
	var marshalledPayload []byte

	if payload != nil {
		var err error
		marshalledPayload, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("error processing json payload (Fireblocks): %v", err)
		}
		stringPayload = string(marshalledPayload)
	}

	token, err := f.kto.createAndSignJWTToken(path, stringPayload)
	if err != nil {
		return []byte{}, fmt.Errorf("error signing JWT token (Fireblocks): %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, f.apiBaseURL+path, bytes.NewBuffer(marshalledPayload))
	if err != nil {
		return []byte{}, fmt.Errorf("error creating request to Fireblocks: %v", err)
	}
	request.Header.Add("X-API-Key", string(f.kto.apiKey))
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))
	request.Header.Add("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return []byte{}, fmt.Errorf("error during request to Fireblocks: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("error reading response from Fireblocks: %v", err)
	}

	return body, err
}
