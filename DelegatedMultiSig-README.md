# DelegatedMultiSig Class

A comprehensive implementation of Taproot-based delegated multi-signature functionality for NBitcoin, enabling an owner to delegate signing authority to a k-of-n multisig scheme while retaining full control through key spending.

## Overview

The `DelegatedMultiSig` class implements a Taproot address where:
- The **owner** can always spend using the key spend path
- A **k-of-n multisig** can spend using the script spend path
- All possible k-combinations of signers are represented as separate TapScript leaves

This design is based on the `CanSignUsingTapscriptAndKeySpend` test and generalizes the concept for practical use.

## Key Features

### 1. Address Generation
- Creates Taproot addresses with both key spend and script spend capabilities
- Supports creation from individual public keys or extended public keys
- Automatic generation of all k-of-n script combinations

### 2. Signature Workflows
- **Key Spend**: Owner can sign and spend immediately (automatically sets key spend mode)
- **Script Spend**: Multi-party signing workflow with partial signatures
- **Automatic Script Selection**: Signers automatically sign all scripts they participate in
- **Serializable Partial Signatures**: Pass signing data between parties as strings
- **PSBT Support**: Basic PSBT integration for standardized workflows

### 3. Transaction Fee Calculation
- **Participant-Aware Size Estimation**: Accurately calculates sizes based on specific signers involved
- **Perfect Fee Prediction**: 100% accurate fee calculation using actual transaction structure
- **Configurable Buffer**: Conservative estimates from 0% to 100% for unpredictable network conditions  
- **Path Comparison**: Compare costs between key spend and script spend options
- **First-Signer Calculation**: First signer calculates and stores accurate sizes for all participating scripts

### 4. Security Model
- Owner always retains control (can spend unilaterally)
- Multisig provides delegation without loss of ultimate control
- Each script combination is cryptographically distinct

## Usage Examples

### Basic Address Creation

```csharp
var ownerKey = new Key();
var ownerPubKey = ownerKey.PubKey; // Only public key stored
var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

// Create 2-of-3 multisig with owner fallback - ONLY public keys stored
var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);
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

var address = DelegatedMultiSig.CreateAddress(ownerExtPubKey, 0u, signerExtKeys, 0u, 2, Network.Main);
```

### Owner Key Spend

```csharp
// Private key is ONLY used during signing, not stored in class
var ownerPrivateKey = new Key(); // Must match the public key used in construction

var builder = multiSig.CreateSignatureBuilder(transaction, coins);
// SignWithOwner automatically sets key spend mode
var signatureData = builder.SignWithOwner(ownerPrivateKey, inputIndex, TaprootSigHash.All);
var finalTx = builder.FinalizeTransaction(inputIndex);
```

### Multi-party Script Spend

```csharp
// First signer (automatically signs all scripts they participate in)
var builder1 = multiSig.CreateSignatureBuilder(transaction, coins);
var sigData1 = builder1.SignWithSigner(signerKey1, inputIndex, TaprootSigHash.All);
var partialSigString = builder1.GetPartialSignatureString(inputIndex);

// Pass partialSigString to second signer...

// Second signer (automatically signs all scripts they participate in)
var builder2 = multiSig.CreateSignatureBuilder(transaction, coins);
var deserializedData = DelegatedMultiSig.PartialSignatureData.Deserialize(partialSigString);
builder2.AddPartialSignature(deserializedData, inputIndex);
var sigData2 = builder2.SignWithSigner(signerKey2, inputIndex, TaprootSigHash.All);

if (sigData2.IsComplete)
{
    var finalTx = builder2.FinalizeTransaction(inputIndex);
}
```

### PSBT Workflow

```csharp
var psbt = multiSig.CreatePSBT(transaction, coins);
// psbt can be passed between parties for signing
// Contains all necessary Taproot information
```

### Transaction Fee Calculation (NEW: Participant-Aware Workflow)

```csharp
// NEW WORKFLOW: Participant-aware fee calculation for perfect accuracy
var transaction = Network.RegTest.CreateTransaction();
transaction.Inputs.Add(new OutPoint(fundingTxId, outputIndex));
transaction.Outputs.Add(paymentAmount, paymentAddress);

// Step 1: Add temporary change output to get correct transaction structure
var feeRate = new FeeRate(Money.Satoshis(25), 1);
var tempFee = feeRate.GetFee(400); // Rough estimate for initial calculation
var tempChange = inputAmount - paymentAmount - tempFee;
transaction.Outputs.Add(tempChange, changeAddress);

// Step 2: First signer calculates accurate sizes for all participating scripts
var builder = multiSig.CreateSignatureBuilder(transaction, coins);
builder.SignWithSigner(firstSignerKey, 0, TaprootSigHash.All); // This calculates and stores accurate sizes

// Step 3: Get participant-aware cheapest script and its accurate virtual size
var participantIndices = new int[] { 0, 1, 2 }; // Indices of actual signers
var cheapestScriptIndex = builder.GetCheapestScriptIndexForSigners(participantIndices);
var accurateVSize = builder.GetActualVirtualSizeForScript(0, cheapestScriptIndex);

// Step 4: Recalculate fee with perfect accuracy and adjust change
var accurateFee = feeRate.GetFee(accurateVSize);
var finalChange = inputAmount - paymentAmount - accurateFee;
transaction.Outputs[1].Value = finalChange; // Update change output

Console.WriteLine($"Participant-aware calculation:");
Console.WriteLine($"  Cheapest script for signers {string.Join(",", participantIndices)}: #{cheapestScriptIndex}");
Console.WriteLine($"  Accurate VSize: {accurateVSize} vbytes (0 error margin)");
Console.WriteLine($"  Perfect fee: {accurateFee}");

// Key spend comparison (if owner available)
if (ownerCanSign)
{
    var keySpendVSize = 110; // Key spend is always ~110 vbytes
    var keySpendFee = feeRate.GetFee(keySpendVSize);
    if (keySpendFee < accurateFee)
    {
        var ownerSigData = builder.SignWithOwner(ownerPrivateKey, 0, TaprootSigHash.All);
        var finalTx = builder.FinalizeTransaction(0);
        return finalTx;
    }
}

// Continue with remaining signers
var finalBuilder = multiSig.CreateSignatureBuilder(transaction, coins);
foreach (var signerIndex in participantIndices)
{
    var sigData = finalBuilder.SignWithSigner(signerKeys[signerIndex], 0, TaprootSigHash.All);
    if (sigData.IsComplete) break;
}

var completedTx = finalBuilder.FinalizeTransaction(0);
// Actual size will exactly match accurateVSize (0 error margin)
```

## API Reference

### TransactionSizeEstimate Class

Provides transaction size estimates for fee calculation:

```csharp
public class TransactionSizeEstimate
{
    public int KeySpendSize { get; set; }
    public int KeySpendVirtualSize { get; set; }
    public Dictionary<int, int> ScriptSpendSizes { get; set; }
    public Dictionary<int, int> ScriptSpendVirtualSizes { get; set; }
    public Dictionary<int, int> ScriptSpendSizesWithBuffer { get; set; }
    public Dictionary<int, int> ScriptSpendVirtualSizesWithBuffer { get; set; }
    
    public int GetEstimatedSize(bool isKeySpend, int scriptIndex = -1, bool useBuffer = false);
    public int GetVirtualSize(bool isKeySpend, int scriptIndex = -1, bool useBuffer = false);
    public int GetVirtualSizeWithCustomBuffer(bool isKeySpend, double bufferPercentage, int scriptIndex = -1);
    public int GetSizeWithCustomBuffer(bool isKeySpend, double bufferPercentage, int scriptIndex = -1);
}
```

### Key Methods

#### Traditional Size Estimation (Generic)
- `GetSizeEstimate(int inputIndex)`: Returns generic size estimates for all scripts
- `GetSizeEstimateWithCustomBuffer(int inputIndex, double bufferPercentage)`: Returns generic size estimates with custom buffer (0-100%)

#### NEW: Participant-Aware Methods (Accurate)
- `GetCheapestScriptIndexForSigners(int[] signerIndices)`: Returns cheapest script index for specific participants
- `GetActualVirtualSizeForScript(int inputIndex, int scriptIndex, bool useBufferedSize)`: Returns stored accurate virtual size for specific script (calculated during signing)

#### Signing Methods
- `SignWithOwner(Key ownerPrivateKey, int inputIndex, TaprootSigHash sigHash)`: Owner signing (automatically sets key spend mode)
- `SignWithSigner(Key signerKey, int inputIndex, TaprootSigHash sigHash)`: Signer signing (calculates and stores accurate sizes for all participating scripts)
- `FinalizeTransaction(int inputIndex)`: Complete transaction with collected signatures (uses stored accurate sizes)

#### Deprecated Methods
- `UseKeySpend()`: (Deprecated) Configure builder for owner key spend - no longer needed
- `UseScript(int scriptIndex)`: (Deprecated) Configure builder for specific script combination

## Architecture Details

### Script Generation

For a k-of-n multisig, the class generates C(n,k) combinations. Each combination becomes a TapScript:

```
Script: pubkey1 OP_CHECKSIG pubkey2 OP_CHECKSIGADD ... k OP_NUMEQUAL
```

**BIP387 Compliance**: 
- For k ≤ 16: Uses OP_k opcodes (OP_1 through OP_16)
- For k > 16: Uses raw number encoding as per BIP387

### Taproot Structure

```
Internal Key: Owner's public key
Scripts: All k-of-n combinations as TapScript leaves
Output: Taproot address supporting both spend paths
```

### Signature Ordering

Following Bitcoin protocol, signatures in witness must be in reverse order of public keys in the script.

### Transaction Size Estimation

The class pre-calculates transaction sizes and virtual sizes (vsize) for accurate fee estimation:

- **Key Spend**: ~160 bytes total, ~110 vbytes (with witness discount)
- **Script Spend**: Varies by k and n (base + k * 64-byte signatures + script + control block)
- **Virtual Size**: Used for fee calculation in SegWit/Taproot transactions
  - Formula: vsize = (base_size * 3 + total_size) / 4
  - Accounts for witness discount (witness data counts as 1/4 weight)
- **Configurable Buffer**: Set any buffer percentage from 0% to 100%
  - Default: 5% buffer for conservative estimates
  - Custom: Use `GetSizeEstimateWithCustomBuffer()` or `GetVirtualSizeWithCustomBuffer()`
  - Emergency: 100% buffer doubles the estimated size for extreme network conditions

Example sizes for common configurations:
- 2-of-3 multisig: ~250-300 bytes (~175-225 vbytes) per script spend
- 3-of-5 multisig: ~350-400 bytes (~250-300 vbytes) per script spend
- Key spend is always the most economical option when available

**Buffer Examples**:
- 0% buffer: Exact calculated size (risky in volatile conditions)
- 5% buffer: Default conservative approach
- 25% buffer: High confidence for network congestion
- 50% buffer: Very conservative for extreme conditions
- 100% buffer: Emergency double-fee approach

**Important**: Always use virtual size (vsize) for fee calculations, not total size

## Security Considerations

1. **Owner Control**: The owner key always allows spending, providing ultimate control
2. **Script Isolation**: Each k-combination is a separate script leaf
3. **Signature Verification**: All signatures use proper Taproot signing procedures
4. **No Key Reuse**: Each address should use unique keys
5. **Private Key Separation**: Private keys are NEVER stored in the class, only used during signing
6. **Key Validation**: The class validates that provided private keys match the stored public keys

## Testing

Comprehensive test suite included in `DelegatedMultiSigTests.cs`:
- Address generation and validation
- Key spend functionality
- Multi-party script spend workflows
- Partial signature serialization
- PSBT integration
- Error handling and edge cases
- Transaction size estimation accuracy
- Fee calculation workflows
- BIP387 compliance for large k values

## Limitations

1. **HAS_SPAN Requirement**: Class requires `HAS_SPAN` compilation flag (Taproot support)
2. **Network Compatibility**: Designed for Bitcoin networks supporting Taproot
3. **Script Complexity**: Number of scripts grows as C(n,k), consider performance for large n
4. **Combination Limit**: Maximum 1,000,000 script combinations to prevent memory exhaustion

## BIP Compatibility

- **BIP 340**: Schnorr signatures
- **BIP 341**: Taproot
- **BIP 342**: Tapscript
- **BIP 174**: PSBT (basic support)
- **BIP 370**: PSBT v2 (basic support)
- **BIP 387**: Tapscript Multisig Output Script Descriptors (k-of-n encoding)

This implementation provides a secure and flexible foundation for delegated multisig scenarios while maintaining the owner's ultimate control over funds.
