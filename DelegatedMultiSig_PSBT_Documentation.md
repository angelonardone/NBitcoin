# DelegatedMultiSig PSBT Implementation Documentation

## Overview

This document describes the BIP 174 compliant PSBT (Partially Signed Bitcoin Transaction) implementation for DelegatedMultiSig in NBitcoin. The implementation enables distributed signing workflows where signers are on different computers and communicate via serialized PSBTs.

## Background

### What is DelegatedMultiSig?

DelegatedMultiSig is a Taproot-based k-of-n multisig implementation that uses script path spending with optimal script combinations. Unlike traditional OP_CHECKMULTISIG which is limited to 15-20 participants, DelegatedMultiSig can support larger sets of signers by utilizing Taproot's script tree capabilities.

### Why PSBT Support?

PSBT (BIP 174) provides a standardized format for passing partially signed transactions between different signers and wallets. For DelegatedMultiSig, PSBT support enables:

1. **Distributed Signing**: Signers on different computers can incrementally add signatures
2. **Interoperability**: Standard format that can be implemented by hardware wallets and other tools
3. **Progressive Fee Selection**: Multiple transaction versions (with different fees) can be signed in parallel, with final signer choosing which to broadcast

## Implementation Details

### BIP Standards Compliance

The implementation follows these Bitcoin Improvement Proposals:

- **BIP 174**: Base PSBT specification for partially signed transactions
- **BIP 341**: Taproot specification for script path spending
- **BIP 371**: PSBT fields for Taproot (referenced but NBitcoin lacks full support)
- **BIP 370**: PSBT Version 2 (general improvements)

Since NBitcoin doesn't implement BIP 371's `PSBT_IN_TAP_SCRIPT_SIG` field (0x14), this implementation uses BIP 174 proprietary fields to store DelegatedMultiSig partial signatures.

### Proprietary Field Format

DelegatedMultiSig signatures are stored in PSBT Unknown fields using BIP 174 proprietary key format:

```
Key Format:
  0xFC                           // Proprietary type byte
  <compact_size:identifier_len>  // Length of identifier (5 bytes)
  "DMSIG"                        // Identifier (5 ASCII bytes)
  <compact_size:scriptIndex>     // Which script combination was used
  <byte:signerIndex>             // Which signer created this signature

Value Format:
  <TaprootSignature>             // Taproot signature bytes (64 or 65 bytes)
```

### Compact Size Encoding

Per Bitcoin protocol, compact size integers are encoded as:

- `< 0xFD`: 1 byte (the value itself)
- `0xFD`: 3 bytes (0xFD + 2-byte little-endian value)
- `0xFE`: 5 bytes (0xFE + 4-byte little-endian value)
- `0xFF`: 9 bytes (0xFF + 8-byte little-endian value)

## API Reference

### CreatePSBT

```csharp
public PSBT CreatePSBT(Transaction transaction, ICoin[] coins)
```

Creates a new PSBT from an unsigned transaction and spent coins.

**Parameters:**
- `transaction`: Unsigned transaction with inputs and outputs
- `coins`: Array of coins being spent (must match transaction inputs)

**Returns:** PSBT ready for signing

**Example:**
```csharp
var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 3, Network.RegTest);
var tx = multiSig.CreateTransaction(coin, paymentAddress, amount, changeAddress, feeRate, signerIndices);
var psbt = multiSig.CreatePSBT(tx, new[] { coin });
```

### SignPSBT

```csharp
public PSBT SignPSBT(PSBT psbt, Key signerKey, int inputIndex = 0,
                     TaprootSigHash sigHash = TaprootSigHash.Default)
```

Signs a PSBT with a signer's key, adding partial signatures for all scripts the signer participates in. The PSBT is modified in-place and returned for chaining.

**Parameters:**
- `psbt`: PSBT to sign (modified in-place)
- `signerKey`: Private key of the signer
- `inputIndex`: Index of the input to sign (default: 0)
- `sigHash`: Taproot signature hash type (default: Default)

**Returns:** The modified PSBT with signatures added

**Throws:**
- `ArgumentException`: If signer key is not found in multisig configuration

**Example:**
```csharp
// Signer 0 signs the PSBT
multiSig.SignPSBT(psbt, signerKeys[0], 0, TaprootSigHash.All);

// Serialize for transmission to next signer
var serialized = psbt.ToBase64();

// Signer 2 receives and signs
var psbt2 = PSBT.Parse(serialized, Network.RegTest);
multiSig.SignPSBT(psbt2, signerKeys[2], 0, TaprootSigHash.All);
```

### FinalizePSBT

```csharp
public Transaction FinalizePSBT(PSBT psbt, int inputIndex = 0, bool useBufferedSize = false)
```

Finalizes a PSBT by extracting partial signatures and creating the final witness. Returns a fully signed transaction ready for broadcast.

**Parameters:**
- `psbt`: PSBT containing all required signatures
- `inputIndex`: Index of the input to finalize (default: 0)
- `useBufferedSize`: Whether to use buffered size estimation (default: false)

**Returns:** Fully signed transaction ready for broadcast

**Throws:**
- `InvalidOperationException`: If insufficient signatures are present

**Example:**
```csharp
// After all signers have signed
var finalTx = multiSig.FinalizePSBT(psbt, 0);

// Broadcast
var txid = rpc.SendRawTransaction(finalTx);
```

## Usage Patterns

### Basic Progressive Signing Workflow

```csharp
// Setup
var ownerKey = new Key();
var signerKeys = new List<Key> { new Key(), new Key(), new Key(), new Key(), new Key() };
var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();
var multiSig = new DelegatedMultiSig(ownerKey.PubKey, signerPubKeys, 3, Network.RegTest);

// Phase 1: First signer creates and signs PSBT
var tx = multiSig.CreateTransaction(coin, paymentAddress, amount, changeAddress,
                                    feeRate, new[] { 0, 2, 4 });
var psbt = multiSig.CreatePSBT(tx, new[] { coin });
multiSig.SignPSBT(psbt, signerKeys[0], 0, TaprootSigHash.All);
var serialized = psbt.ToBase64();

// Phase 2: Second signer receives, deserializes, and signs
var psbt2 = PSBT.Parse(serialized, Network.RegTest);
multiSig.SignPSBT(psbt2, signerKeys[2], 0, TaprootSigHash.All);
serialized = psbt2.ToBase64();

// Phase 3: Final signer receives, signs, and finalizes
var psbt3 = PSBT.Parse(serialized, Network.RegTest);
multiSig.SignPSBT(psbt3, signerKeys[4], 0, TaprootSigHash.All);
var finalTx = multiSig.FinalizePSBT(psbt3, 0);

// Broadcast
var txid = rpc.SendRawTransaction(finalTx);
```

### Dual-Buffer Progressive Signing

This pattern allows creating multiple transaction versions with different fee rates, signing all of them progressively, and having the final signer choose which to broadcast based on current network conditions.

```csharp
// Create THREE transactions with different fees
var (baseTx, buffer5Tx) = multiSig.CreateDualTransactions(
    coin, paymentAddress, paymentAmount, changeAddress, feeRate,
    new[] { 0, 2, 4 }, bufferPercentage: 5.0);

var (_, buffer10Tx) = multiSig.CreateDualTransactions(
    coin, paymentAddress, paymentAmount, changeAddress, feeRate,
    new[] { 0, 2, 4 }, bufferPercentage: 10.0);

// Phase 1: First signer creates and signs all three PSBTs
var psbtBase = multiSig.CreatePSBT(baseTx, new[] { coin });
var psbtBuffer5 = multiSig.CreatePSBT(buffer5Tx, new[] { coin });
var psbtBuffer10 = multiSig.CreatePSBT(buffer10Tx, new[] { coin });

multiSig.SignPSBT(psbtBase, signerKeys[0], 0, TaprootSigHash.All);
multiSig.SignPSBT(psbtBuffer5, signerKeys[0], 0, TaprootSigHash.All);
multiSig.SignPSBT(psbtBuffer10, signerKeys[0], 0, TaprootSigHash.All);

// Serialize all three
var serializedBase = psbtBase.ToBase64();
var serializedBuffer5 = psbtBuffer5.ToBase64();
var serializedBuffer10 = psbtBuffer10.ToBase64();

// Phase 2: Second signer receives and signs all three
var psbtBase2 = PSBT.Parse(serializedBase, Network.RegTest);
var psbtBuffer5_2 = PSBT.Parse(serializedBuffer5, Network.RegTest);
var psbtBuffer10_2 = PSBT.Parse(serializedBuffer10, Network.RegTest);

multiSig.SignPSBT(psbtBase2, signerKeys[2], 0, TaprootSigHash.All);
multiSig.SignPSBT(psbtBuffer5_2, signerKeys[2], 0, TaprootSigHash.All);
multiSig.SignPSBT(psbtBuffer10_2, signerKeys[2], 0, TaprootSigHash.All);

// Re-serialize
serializedBase = psbtBase2.ToBase64();
serializedBuffer5 = psbtBuffer5_2.ToBase64();
serializedBuffer10 = psbtBuffer10_2.ToBase64();

// Phase 3: Final signer decides which to finalize and broadcast
var psbtBase4 = PSBT.Parse(serializedBase, Network.RegTest);
var psbtBuffer5_4 = PSBT.Parse(serializedBuffer5, Network.RegTest);
var psbtBuffer10_4 = PSBT.Parse(serializedBuffer10, Network.RegTest);

multiSig.SignPSBT(psbtBase4, signerKeys[4], 0, TaprootSigHash.All);
multiSig.SignPSBT(psbtBuffer5_4, signerKeys[4], 0, TaprootSigHash.All);
multiSig.SignPSBT(psbtBuffer10_4, signerKeys[4], 0, TaprootSigHash.All);

// Finalize all three
var finalBaseTx = multiSig.FinalizePSBT(psbtBase4, 0);
var finalBuffer5Tx = multiSig.FinalizePSBT(psbtBuffer5_4, 0);
var finalBuffer10Tx = multiSig.FinalizePSBT(psbtBuffer10_4, 0);

// Check network conditions and choose which to broadcast
if (networkCongestionHigh)
    var txid = rpc.SendRawTransaction(finalBuffer10Tx);  // Higher fee
else
    var txid = rpc.SendRawTransaction(finalBaseTx);  // Lower fee
```

## Testing

### Test Coverage

The implementation includes comprehensive tests:

1. **CanUsePSBTWorkflow** - Basic PSBT creation and signing
2. **DualBufferProgressiveSigning_3of5_PSBT** - Progressive signing with dual buffers
3. **PSBT_BIP174_Compliance_Test** - Full BIP 174 compliance verification

### Running Tests

```bash
# Run all PSBT-related tests
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
dotnet test ./NBitcoin.Tests/NBitcoin.Tests.csproj -c Release -f net6.0 \
    --filter "FullyQualifiedName~PSBT" \
    -p:ParallelizeTestCollections=false

# Run specific test
dotnet test ./NBitcoin.Tests/NBitcoin.Tests.csproj -c Release -f net6.0 \
    --filter "FullyQualifiedName~PSBT_BIP174_Compliance_Test" \
    -p:ParallelizeTestCollections=false
```

### Example Test Output

```
=== BIP 174 Compliant PSBT Implementation Test ===
Testing progressive signing with serialized PSBTs
📋 Created 3-of-5 multisig
   • Address: bcrt1p7e2trds3lkreumf4rervxkk2dhxujh769fawp4q0zwqtx8kffc9sdmmkl5
✓ Funded with 1.00000000

👥 Participating signers: #0, #2, #4

💰 Creating three transaction versions:
   • Base transaction: Fee = 0.00011150 (11150 sats)
   • 5% buffer: Fee = 0.00011700 (11700 sats)
   • 10% buffer: Fee = 0.00012250 (12250 sats)

🔏 Phase 1: Signer #0 creates and signs PSBTs for all three transactions
   ✓ Signed base transaction PSBT
   ✓ Signed 5% buffer transaction PSBT
   ✓ Signed 10% buffer transaction PSBT
   ✓ Proprietary fields added to PSBT inputs
   📦 Serialized PSBTs for transmission
      • Base: 932 characters
      • 5% buffer: 932 characters
      • 10% buffer: 932 characters

🔏 Phase 2: Signer #2 receives and signs all three PSBTs
   ✓ Proprietary fields preserved through serialization
   ✓ Added signatures to base transaction PSBT
   ✓ Added signatures to 5% buffer transaction PSBT
   ✓ Added signatures to 10% buffer transaction PSBT
   📦 Re-serialized PSBTs with two signers

🔏 Phase 3: Final signer #4 receives, signs, and decides
   ✓ All three PSBTs now have 3 signatures

📏 Final transaction sizes:
   • Base: 222 vbytes, Fee: 0.00011150
   • 5% buffer: 222 vbytes, Fee: 0.00011700
   • 10% buffer: 222 vbytes, Fee: 0.00012250

✅ Validating all three transactions:
   ✓ All three have correct payment amount
   ✓ All three have positive change
   ✓ Fees are correctly ordered: base < 5% < 10%

📡 Final decision: Broadcasting 5% buffer transaction
   • Chosen fee: 0.00011700
   • Change returned: 0.19988300
   ✅ Transaction accepted! Txid: f53cee29d9063fedcbc5238868ba37e811280c6b73367223356557f71f223c45
   ✅ Transaction confirmed in mempool

✅ SUCCESS: BIP 174 compliant PSBT workflow verified!
```

## Technical Implementation Details

### Helper Methods

#### GetCompactSizeBytes

```csharp
private static byte[] GetCompactSizeBytes(ulong value)
```

Encodes a value as Bitcoin compact size format. Handles all four encoding types:
- Values < 0xFD: Single byte
- Values ≤ 0xFFFF: 0xFD + 2-byte little-endian
- Values ≤ 0xFFFFFFFF: 0xFE + 4-byte little-endian
- Values > 0xFFFFFFFF: 0xFF + 8-byte little-endian

#### ReadCompactSizeFromBytes

```csharp
private static ulong ReadCompactSizeFromBytes(byte[] data, ref int offset)
```

Reads a compact size value from a byte array, advancing the offset. Properly handles all four encoding types and validates bounds.

### SignPSBT Implementation Flow

1. **Validate Signer**: Verify signer's public key is in the multisig configuration
2. **Extract Transaction Data**: Get transaction and coins from PSBT
3. **Create Builder**: Use `CreateSignatureBuilder()` with transaction and coins
4. **Generate Signatures**: Call `SignWithSigner()` to create partial signatures
5. **Encode Proprietary Keys**: For each signature:
   - Create identifier bytes: "DMSIG" (5 bytes)
   - Encode scriptIndex as compact size
   - Add signerIndex as single byte
   - Build BIP 174 compliant key: `0xFC + <cs:5> + "DMSIG" + <cs:scriptIndex> + signerIndex`
6. **Store in PSBT**: Add to `psbt.Inputs[inputIndex].Unknown` dictionary
7. **Return PSBT**: Modified PSBT with signatures added

### FinalizePSBT Implementation Flow

1. **Extract Transaction Data**: Get transaction and coins from PSBT
2. **Create Builder**: Use `CreateSignatureBuilder()` with transaction and coins
3. **Parse Proprietary Fields**: For each entry in `Unknown`:
   - Check if key starts with 0xFC (proprietary)
   - Read identifier length (compact size)
   - Read identifier and verify it's "DMSIG"
   - Read scriptIndex (compact size)
   - Read signerIndex (single byte)
   - Parse TaprootSignature from value
   - Reconstruct `PartialSignature` object
4. **Add to Builder**: Add all partial signatures to builder
5. **Finalize**: Call `FinalizeTransaction()` to create witness
6. **Return Transaction**: Fully signed transaction ready for broadcast

## Key Design Decisions

### Why Proprietary Fields?

NBitcoin doesn't implement BIP 371's `PSBT_IN_TAP_SCRIPT_SIG` field (0x14) for Taproot script path signatures. Rather than extending NBitcoin's PSBT implementation (which would be a large undertaking), we use BIP 174 proprietary fields which are:

- Standards-compliant per BIP 174
- Suitable for application-specific data
- Preserved through PSBT serialization/deserialization
- Compatible with existing PSBT infrastructure

### Why "DMSIG" Identifier?

The 5-byte identifier "DMSIG" stands for "DelegatedMultiSig" and uniquely identifies these proprietary fields. This prevents conflicts with other proprietary field users.

### Script Index Storage

DelegatedMultiSig generates multiple script combinations for a k-of-n multisig. The `scriptIndex` identifies which script combination a particular signature is for. This allows:

- Multiple signatures from the same signer for different scripts
- Efficient lookup during finalization
- Proper combination selection based on participating signers

## Limitations and Considerations

### Current Limitations

1. **Single Input Support**: Current implementation focuses on single-input transactions. Multi-input support would require per-input PSBT handling.

2. **Not Standard BIP 371**: Uses proprietary fields instead of BIP 371 Taproot fields. This means hardware wallets won't natively understand DelegatedMultiSig PSBTs without custom firmware.

3. **No Key Path Spending**: Implementation focuses on script path. Key path spending (MuSig) is handled by DelegatedMultiSig2.

### Security Considerations

1. **Signature Validation**: FinalizePSBT validates signatures during finalization. Invalid signatures are rejected.

2. **Signer Authorization**: SignPSBT verifies the signer is part of the multisig configuration before signing.

3. **Threshold Enforcement**: FinalizeTransaction enforces the k-of-n threshold requirement.

4. **Serialization Safety**: PSBT format ensures signatures can't be corrupted during transmission.

## Future Enhancements

Potential improvements for future versions:

1. **Multi-Input Support**: Extend to handle multiple inputs per transaction
2. **BIP 371 Integration**: If NBitcoin adds BIP 371 support, migrate from proprietary fields
3. **Hardware Wallet Support**: Work with hardware wallet vendors to support DelegatedMultiSig
4. **PSBT Version 2**: Upgrade to BIP 370 PSBT v2 format
5. **Batch Signing**: Optimize for signing multiple PSBTs in one operation

## References

- [BIP 174: Partially Signed Bitcoin Transaction Format](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
- [BIP 341: Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP 370: PSBT Version 2](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
- [BIP 371: Taproot Fields for PSBT](https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki)

## Support

For issues, questions, or contributions related to DelegatedMultiSig PSBT support:

- Review the test files: `/NBitcoin.Tests/DelegatedMultiSigTests.cs`
- Check the implementation: `/NBitcoin/DelegatedMultiSig.cs`
- See working examples in the test suite

## Changelog

### 2025-10-02 - Initial Implementation
- Added `CreatePSBT()`, `SignPSBT()`, and `FinalizePSBT()` methods
- Implemented BIP 174 compliant proprietary field format
- Added compact size encoding/decoding helpers
- Created comprehensive test suite
- Verified with actual Bitcoin RegTest network
