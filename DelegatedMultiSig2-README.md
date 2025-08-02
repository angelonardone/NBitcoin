# DelegatedMultiSig2 Class

A comprehensive implementation of Taproot-based delegated multi-signature functionality using MuSig2 for NBitcoin, enabling an owner to delegate signing authority to a k-of-n multisig scheme while retaining full control through key spending.

## Overview

The `DelegatedMultiSig2` class implements a Taproot address where:
- The **owner** can always spend using the key spend path
- A **k-of-n multisig** can spend using the script spend path with **MuSig2 aggregated signatures**
- Each script contains a single aggregated public key instead of multiple individual keys
- All k-combinations of signers are represented as separate TapScript leaves with aggregated keys

This design uses **MuSig2** protocol which requires interactive nonce exchange before signing, unlike the sequential signing approach of traditional multisig.

## Key Features

### 1. MuSig2 Protocol Implementation
- Uses Schnorr signature aggregation for k-of-n multisig
- Each script contains a single aggregated public key with `OP_CHECKSIG`
- Requires two-phase interactive protocol: nonce exchange then signing
- All participants must be "online" during the signing process

### 2. Two-Phase Signing Process
- **Phase 1 (Nonce Exchange)**: All signers must generate and exchange public nonces
- **Phase 2 (Signing)**: Required signers create partial signatures that are aggregated
- **Interactive Nature**: Unlike DelegatedMultiSig, all signers must coordinate in real-time

### 3. Address Generation
- Creates Taproot addresses with both key spend and script spend capabilities
- Supports creation from individual public keys or extended public keys
- Automatic generation of all k-of-n script combinations with aggregated keys

### 4. Signature Workflows
- **Key Spend**: Owner can sign and spend immediately (automatically sets key spend mode)
- **Script Spend**: Multi-party interactive signing workflow with nonce exchange
- **Nonce Coordination**: Built-in nonce exchange mechanism with serialization support
- **Signature Aggregation**: MuSig2-based aggregation of partial signatures

### 5. Serialization and Network Support
- **Nonce Data Serialization**: `MuSig2NonceData` can be serialized for network transmission
- **Nonce Exchange Coordination**: `MuSig2NonceExchange` manages multi-party nonce sharing
- **Partial Signature Support**: Signatures can be serialized and combined
- **PSBT Integration**: Basic PSBT support for standardized workflows

### 6. Security Model
- Owner always retains control (can spend unilaterally via key spend)
- MuSig2 provides cryptographic security with signature aggregation
- Each script combination uses a unique aggregated public key
- Interactive protocol prevents signature replay attacks

## Usage Examples

### Basic Address Creation

```csharp
var ownerKey = new Key();
var ownerPubKey = ownerKey.PubKey; // Only public key stored
var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

// Create 2-of-3 MuSig2 multisig with owner fallback - ONLY public keys stored
var multiSig = new DelegatedMultiSig2(ownerPubKey, signerPubKeys, 2, Network.RegTest);
var address = multiSig.Address;
```

### Extended Key Support

```csharp
var mnemo = new Mnemonic("abandon abandon...");
var root = mnemo.DeriveExtKey();

var ownerExtPubKey = root.Derive(new KeyPath("m/86'/0'/0'")).Neuter(); // Only public key
var signerExtKeys = new List<ExtPubKey>
{
    root.Derive(new KeyPath("m/86'/0'/1'")).Neuter(),
    root.Derive(new KeyPath("m/86'/0'/2'")).Neuter(),
    root.Derive(new KeyPath("m/86'/0'/3'")).Neuter()
};

var address = DelegatedMultiSig2.CreateAddress(ownerExtPubKey, 0u, signerExtKeys, 0u, 2, Network.Main);
```

### Owner Key Spend

```csharp
// Private key is ONLY used during signing, not stored in class
var ownerPrivateKey = new Key(); // Must match the public key used in construction

var builder = multiSig.CreateSignatureBuilder(transaction, coins);
// SignWithOwner automatically sets key spend mode
var signatureData = builder.SignWithOwner(ownerPrivateKey, inputIndex, TaprootSigHash.All);
var finalTx = signatureData.Transaction; // Already finalized for key spend
```

### Multi-party MuSig2 Script Spend

```csharp
var builder = multiSig.CreateSignatureBuilder(transaction, coins);

// Phase 1: ALL signers must generate and exchange nonces
var nonceData0 = builder.GenerateNonce(signerKey0, inputIndex, TaprootSigHash.All);
var nonceData1 = builder.GenerateNonce(signerKey1, inputIndex, TaprootSigHash.All);
var nonceData2 = builder.GenerateNonce(signerKey2, inputIndex, TaprootSigHash.All);

// Exchange nonces between all parties (all must have all nonces)
builder.AddNonces(nonceData0, inputIndex);
builder.AddNonces(nonceData1, inputIndex);
builder.AddNonces(nonceData2, inputIndex);

// Phase 2: Required signers create partial signatures (for 2-of-3, any 2 signers)
var sigData1 = builder.SignWithSigner(signerKey1, inputIndex, TaprootSigHash.All);
var sigData2 = builder.SignWithSigner(signerKey2, inputIndex, TaprootSigHash.All);

if (sigData2.IsComplete)
{
    var finalTx = builder.FinalizeTransaction(inputIndex);
}
```

### Distributed Nonce Exchange

```csharp
// Signer 0 generates nonces
var builder0 = multiSig.CreateSignatureBuilder(transaction, coins);
var nonceData0 = builder0.GenerateNonce(signerKey0, inputIndex);
var nonceString0 = nonceData0.Serialize(); // Send over network

// Signer 1 generates nonces
var builder1 = multiSig.CreateSignatureBuilder(transaction, coins);
var nonceData1 = builder1.GenerateNonce(signerKey1, inputIndex);  
var nonceString1 = nonceData1.Serialize(); // Send over network

// Signer 2 generates nonces
var builder2 = multiSig.CreateSignatureBuilder(transaction, coins);
var nonceData2 = builder2.GenerateNonce(signerKey2, inputIndex);
var nonceString2 = nonceData2.Serialize(); // Send over network

// Each signer receives and adds all nonces
var receivedNonce1 = DelegatedMultiSig2.MuSig2NonceData.Deserialize(nonceString1);
var receivedNonce2 = DelegatedMultiSig2.MuSig2NonceData.Deserialize(nonceString2);
builder0.AddNonces(receivedNonce1, inputIndex);
builder0.AddNonces(receivedNonce2, inputIndex);

// Now signer 0 can sign (repeat for other signers)
var sigData = builder0.SignWithSigner(signerKey0, inputIndex);
```

### PSBT Workflow

```csharp
var psbt = multiSig.CreatePSBT(transaction, coins);
// psbt can be passed between parties for signing
// Contains all necessary Taproot information
// Note: PSBT workflow with MuSig2 requires custom nonce coordination
```

## API Reference

### Main Classes

#### DelegatedMultiSig2
Main class for creating MuSig2-based delegated multisig addresses.

```csharp
public DelegatedMultiSig2(PubKey ownerPubKey, List<PubKey> signerPubKeys, int requiredSignatures, Network network)
public TaprootAddress Address { get; }
public TaprootPubKey TaprootPubKey { get; }
public IReadOnlyList<TapScript> Scripts { get; }
```

#### MuSig2SignatureBuilder
Handles the interactive MuSig2 signing workflow.

```csharp
public MuSig2NonceData GenerateNonce(Key signerKey, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
public void AddNonces(MuSig2NonceData nonceData, int inputIndex)
public MuSig2SignatureData SignWithSigner(Key signerKey, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
public MuSig2SignatureData SignWithOwner(Key ownerPrivateKey, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
public Transaction FinalizeTransaction(int inputIndex)
```

#### MuSig2NonceExchange
Manages nonce coordination between signers.

```csharp
public class MuSig2NonceExchange
{
    public int InputIndex { get; set; }
    public int ScriptIndex { get; set; }
    public bool IsComplete { get; set; }
    public byte[] SignatureHash { get; set; }
    
    public string Serialize()
    public static MuSig2NonceExchange Deserialize(string serialized)
}
```

#### MuSig2NonceData
Contains nonce information for a specific signer.

```csharp
public class MuSig2NonceData
{
    public int SignerIndex { get; set; }
    public List<MuSig2NonceExchange> NonceExchanges { get; set; }
    
    public string Serialize()
    public static MuSig2NonceData Deserialize(string serialized)
}
```

#### MuSig2SignatureData
Contains signature information and completion status.

```csharp
public class MuSig2SignatureData
{
    public Transaction Transaction { get; set; }
    public int InputIndex { get; set; }
    public bool IsComplete { get; set; }
    public bool IsKeySpend { get; set; }
}
```

### Key Methods

- `GenerateNonce(Key signerKey, int inputIndex, TaprootSigHash sigHash)`: Generate nonces for all scripts a signer participates in
- `AddNonces(MuSig2NonceData nonceData, int inputIndex)`: Add received nonces from other signers
- `SignWithOwner(Key ownerPrivateKey, int inputIndex, TaprootSigHash sigHash)`: Owner key spend signing
- `SignWithSigner(Key signerKey, int inputIndex, TaprootSigHash sigHash)`: MuSig2 partial signature creation
- `FinalizeTransaction(int inputIndex)`: Aggregate partial signatures and complete transaction

## Architecture Details

### Script Generation (MuSig2)

For a k-of-n multisig, the class generates C(n,k) combinations. Each combination becomes a TapScript with an **aggregated public key**:

```
Traditional: pubkey1 OP_CHECKSIG pubkey2 OP_CHECKSIGADD ... k OP_NUMEQUAL
MuSig2:      aggregated_pubkey OP_CHECKSIG
```

**Key Aggregation Process**:
1. For each k-combination of signers
2. Aggregate their public keys using `ECPubKey.MusigAggregate(selectedPubKeys)`
3. Create script with single aggregated key: `aggregated_key OP_CHECKSIG`

### Taproot Structure

```
Internal Key: Owner's public key
Scripts: All k-of-n combinations as TapScript leaves (each with aggregated keys)
Output: Taproot address supporting both spend paths
```

### MuSig2 Protocol Flow

1. **Setup**: All signers share their public keys for aggregation
2. **Nonce Generation**: Each signer generates private nonces for all scripts they participate in
3. **Nonce Exchange**: All signers exchange public nonces (must be complete before signing)
4. **Partial Signing**: Required signers create partial signatures using their private keys and nonces
5. **Aggregation**: Partial signatures are aggregated into a single Schnorr signature
6. **Finalization**: Transaction is completed with the aggregated signature

### Interactive Requirements

Unlike traditional multisig where signers can sign sequentially:

- **All signers must be online during nonce exchange phase**
- **Nonces must be exchanged before any signing begins**
- **Signatures are aggregated, not concatenated**
- **Each signing session requires fresh nonces**

## Security Considerations

1. **Owner Control**: The owner key always allows spending, providing ultimate control
2. **MuSig2 Security**: Cryptographically secure signature aggregation prevents key substitution attacks
3. **Nonce Safety**: Fresh nonces must be used for each signing session
4. **Interactive Protocol**: All participants must be online, preventing some offline attack vectors
5. **Script Isolation**: Each k-combination uses a unique aggregated public key
6. **Private Key Separation**: Private keys are NEVER stored in the class, only used during signing
7. **Nonce Coordination**: Secure nonce exchange prevents signature forgery

## Differences from DelegatedMultiSig

| Aspect | DelegatedMultiSig (Traditional) | DelegatedMultiSig2 (MuSig2) |
|--------|--------------------------------|----------------------------|
| **Script Structure** | Multiple pubkeys with OP_CHECKSIGADD | Single aggregated pubkey with OP_CHECKSIG |
| **Signing Process** | Sequential (one after another) | Interactive (all coordinate together) |
| **Network Requirements** | Asynchronous signing possible | All signers must be online simultaneously |
| **Signature Size** | Multiple signatures in witness | Single aggregated Schnorr signature |
| **Privacy** | Multiple pubkeys visible on-chain | Only aggregated key visible on-chain |
| **Efficiency** | Larger transaction size | Smaller transaction size |
| **Complexity** | Simpler workflow | More complex interactive protocol |

## Testing

Comprehensive test suite included in `DelegatedMultiSig2Tests.cs`:

### Test Categories
- **Basic Functionality**: Address generation, key validation, script combinations
- **Key Spend**: Owner spending with immediate finalization
- **MuSig2 Protocol**: Full interactive signing workflow with nonce exchange
- **Nonce Coordination**: Serialization, deserialization, and exchange between parties
- **Multi-Input Support**: Handling multiple inputs with separate nonce exchanges
- **Error Handling**: Invalid parameters, incomplete nonces, missing signatures
- **Script Combinations**: Different signer combinations for k-of-n scenarios
- **PSBT Integration**: Basic PSBT workflow support

### Running Tests

```bash
# Run all DelegatedMultiSig2 tests
dotnet test ./NBitcoin.Tests/NBitcoin.Tests.csproj -c Release -f net6.0 --filter "FullyQualifiedName~DelegatedMultiSig2Tests"

# Run specific test categories
dotnet test ./NBitcoin.Tests/NBitcoin.Tests.csproj -c Release -f net6.0 --filter "FullyQualifiedName~DelegatedMultiSig2Tests.CanSpendWithMuSig2"
```

## Limitations

1. **HAS_SPAN Requirement**: Class requires `HAS_SPAN` compilation flag (Taproot support)
2. **Network Compatibility**: Designed for Bitcoin networks supporting Taproot
3. **Interactive Protocol**: All signers must be online during nonce exchange and signing
4. **Combination Limit**: Maximum 1,000,000 script combinations to prevent memory exhaustion
5. **Fresh Nonces**: New nonces required for each signing session (cannot reuse)
6. **Real-time Coordination**: More complex coordination compared to sequential signing

## BIP Compatibility

- **BIP 340**: Schnorr signatures (used in MuSig2)
- **BIP 341**: Taproot
- **BIP 342**: Tapscript
- **BIP 174**: PSBT (basic support)
- **BIP 370**: PSBT v2 (basic support)
- **MuSig2**: Based on the MuSig2 specification for secure signature aggregation

## Use Cases

### Ideal for DelegatedMultiSig2:
- **High-frequency trading**: Where privacy and efficiency matter
- **Corporate treasury**: Where all signers can coordinate in real-time
- **Synchronized operations**: Where all parties are online simultaneously
- **Privacy-focused applications**: Where hiding individual signers is important

### Better suited for DelegatedMultiSig (traditional):
- **Asynchronous workflows**: Where signers are in different time zones
- **Offline signing**: Where signers cannot coordinate in real-time
- **Simple workflows**: Where interactive complexity is undesirable
- **Legacy compatibility**: Where traditional multisig is preferred

This implementation provides a secure and efficient foundation for interactive delegated multisig scenarios using modern MuSig2 cryptography while maintaining the owner's ultimate control over funds.