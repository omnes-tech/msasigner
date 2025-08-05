package fireblocks

import (
	"github.com/shopspring/decimal"
)

type VaultAsset struct {
	Id                   string `json:"id"`
	Total                string `json:"total"`
	Available            string `json:"available"`
	Pending              string `json:"pending"`
	LockedAmount         string `json:"lockedAmount"`
	TotalStackedCPU      string `json:"totalStackedCPU"`
	TotalStackedNetwork  string `json:"totalStackedNetwork"`
	SelfStackedCPU       string `json:"selfStackedCPU"`
	SelfStakedNetwork    string `json:"selfStakedNetwork"`
	PendingRefundCPU     string `json:"pendingRefundCPU"`
	PendingRefundNetwork string `json:"pendingRefundNetwork"`
}

type VaultAccount struct {
	Id            string       `json:"id"`
	Name          string       `json:"name"`
	HiddenOnUI    bool         `json:"hiddenOnUI"`
	CustomerRefId string       `json:"customerRefId"`
	AutoFuel      bool         `json:"autoFuel"`
	Assets        []VaultAsset `json:"assets"`
}

type VaultAccounts struct {
	Accounts []VaultAccount `json:"accounts"`
	Paging   interface{}    `json:"paging"`
}

type VaultAccountAssetAddress struct {
	AssetId           string `json:"assetId"`        // The ID of the asset
	Address           string `json:"address"`        // Address of the asset in a Vault Account, for BTC/LTC the address is in Segwit (Bech32) format, for BCH cash format
	LegacyAddress     string `json:"legacyAddress"`  // For BTC/LTC/BCH the legacy format address
	Description       string `json:"description"`    // Description of the address
	Tag               string `json:"tag"`            // Destination tag for XRP, used as memo for EOS/XLM, for Signet/SEN it is the Bank Transfer Description
	Type              string `json:"type"`           // Address type
	CustomerRefId     string `json:" customerRefId"` // [optional] The ID for AML providers to associate the owner of funds with transactions
	AddressFormat     string `json:"addressFormat"`
	EnterpriseAddress string `json:"enterpriseAddress"`
}

type DestinationTransferPeerPath struct {
	TPeerId   string `json:"id"`
	TPeerType string `json:"type"`
}

type RawMessageDataStruct struct {
	Content string `json:"content" validate:"required"`
}

type Messages struct {
	Messages []RawMessageDataStruct `json:"messages"`
}

type ExtraParameters struct {
	ContractCallData string   `json:"contractCallData"`
	RawMessageData   Messages `json:"rawMessageData"`
}

type CreateTransactionResponse struct {
	Id     string `json:"Id"`
	Status string `json:"status"`
	Error  error
}

type TransferPeerPathResponse struct {
	TransferType string `json:"type"` //[ PTVaultAccount, EXCHANGE_ACCOUNT, INTERNAL_WALLET, EXTERNAL_WALLET, ONE_TIME_ADDRESS, NETWORK_CONNECTION, FIAT_ACCOUNT, COMPOUND ]
	Id           string `json:"id"`   // The ID of the exchange account to return
	Name         string `json:"name"` // The name of the exchange account
	Subtype      string `json:"subType"`
}

type AmountInfo struct {
	Amount          string `json:"amount"`          // If the transfer is a withdrawal from an exchange, the actual amount that was requested to be transferred. Otherwise, the requested amount
	RequestedAmount string `json:"requestedAmount"` //The amount requested by the user
	NetAmount       string `json:"NetAmount"`       // The net amount of the transaction, after fee deduction
	AmountUSD       string `json:"amountUSD"`       // The USD value of the requested amount
}

type FeeInfo struct {
	NetworkFee string `json:"NetworkFee"` // The fee paid to the network
	ServiceFee string `json:"ServiceFee"` // The total fee deducted by the exchange from the actual requested amount (serviceFee = amount - netAmount)
}

type AmlScreeningResult struct {
	Provider string `json:"provider"` // The AML service provider
	Payload  string `json:"payload"`  // The response of the AML service provider
}

type NetworkRecord struct {
	Source             TransferPeerPathResponse `json:"source"`             // Source of the transaction
	Destination        TransferPeerPathResponse `json:"destination"`        // Destination of the transaction
	TxHash             string                   `json:"txHash"`             // Blockchain hash of the transaction
	NetworkFee         decimal.Decimal          `json:"networkFee"`         // The fee paid to the network
	AssetId            string                   `json:"assetId"`            // transaction asset
	NetAmount          decimal.Decimal          `json:"netAmount"`          // The net amount of the transaction, after fee deduction
	Status             string                   `json:"status"`             // Status of the blockchain transaction
	OpType             string                   `json:"type"`               // Type of the operation
	DestinationAddress string                   `json:"destinationAddress"` // Destination address
	SourceAddress      string                   `json:"sourceAddress"`      // For account based assets only, the source address of the transaction

}

type DestinationsResponse struct {
	Amount                        decimal.Decimal          `json:"amount"`                        // The amount to be sent to this destination
	Destination                   TransferPeerPathResponse `json:"destination"`                   // Destination of the transaction
	AmountUSD                     decimal.Decimal          `json:"amountUSD"`                     // The USD value of the requested amount
	DestinationAddress            string                   `json:"destinationAddress"`            // Address where the asset were transfered
	DestinationAddressDescription string                   `json:"destinationAddressDescription"` // Description of the address
	AmlScreeningResult            AmlScreeningResult       `json:"amlScreeningResult"`            // The result of the AML screening
	CustomerRefId                 string                   `json:"customerRefId"`                 // The ID for AML providers to associate the owner of funds with transactions

}

type BlockInfo struct {
	BlockHeight string `json:"blockHeight"`
	BlockHash   string `json:"blockHash"`
}

type FireblocksSignature struct {
	FullSig string `json:"fullSig"`
	R       string `json:"r"`
	S       string `json:"s"`
	V       uint8  `json:"v"`
}

type SignedMessage struct {
	Signature FireblocksSignature `json:"signature"` // The message signature
	PublicKey string              `json:"publicKey"` // Signature's public key that can be used for verification.
}

type TransactionDetails struct {
	Id             string          `json:"id"`             // ID of the transaction
	Status         string          `json:"status"`         // The current status of the transaction
	SignedMessages []SignedMessage `json:"signedMessages"` // A list of signed messages returned for raw signing
}
