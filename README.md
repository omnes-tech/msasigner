# msasigner

A Go package for signing messages and transactions using multiple signing methods including Fireblocks, GCP KMS, private keys, passkeys, and multisig.

## Installation

```bash
go get github.com/omnes-tech/msasigner
```

## Features

- **Fireblocks Signer**: Sign messages using Fireblocks API
- **Private Key Signer**: Sign messages using ECDSA private keys
- **GCP KMS Signer**: Sign messages using Google Cloud KMS
- **Passkey Signer**: Sign messages using WebSocket-based passkey authentication
- **Multisig Signer**: Combine multiple signers for multisig operations

## Usage

### Fireblocks Signer

```go
import (
    "github.com/omnes-tech/msasigner"
    "github.com/omnes-tech/msasigner/fireblocks"
)

// Create a Fireblocks signer
signer, err := msasigner.NewFireblocksSigner(
    apiPrivateKey,
    apiKey,
    clientId,
    assetId,
)
if err != nil {
    log.Fatal(err)
}

// Sign a message
signature, err := signer.SignMessage(message)
```

### Private Key Signer

```go
import "github.com/omnes-tech/msasigner"

// Create a private key signer
signer, err := msasigner.NewPKSigner(privateKeyHex)
if err != nil {
    log.Fatal(err)
}

// Sign a message
signature, err := signer.SignMessage(message)
```

### GCP KMS Signer

```go
import "github.com/omnes-tech/msasigner"

// Create a GCP KMS signer
signer, err := msasigner.NewGCPSigner(
    ctx,
    projectID,
    locationID,
    keyRingID,
    keyID,
    keyVersionID,
)
if err != nil {
    log.Fatal(err)
}

// Sign a message
signature, err := signer.SignMessage(message)
```

### Multisig Signer

```go
import "github.com/omnes-tech/msasigner"

// Create multiple signers
signers := []types.Signer{signer1, signer2, signer3}

// Create a multisig signer
multisig := msasigner.NewMultisigSigner(signers)

// Sign a message (combines all signatures)
signature, err := multisig.SignMessage(message)
```

## Subpackages

### fireblocks

The `fireblocks` subpackage provides a low-level SDK for interacting with the Fireblocks API.

```go
import "github.com/omnes-tech/msasigner/fireblocks"

// Create a Fireblocks SDK instance
sdk, err := fireblocks.NewInstance(privateKey, apiKey, apiURL)
if err != nil {
    log.Fatal(err)
}

// Get vault ID
vaultId, err := sdk.GetVaultId(nameSuffix)

// Get address
address, err := sdk.GetAddress(vaultId, assetId)

// Sign a message
publicKey, r, s, v, err := sdk.Sign(hashedMessage, vaultId, assetId)
```
