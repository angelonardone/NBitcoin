# DelegatedMultiSig PSBT API - Final Design

## The Simplest Possible API

After discussion, the API has been simplified to its absolute minimum:

### Public Methods

**1. SignPSBT** - Add your signature
```csharp
public PSBT SignPSBT(PSBT psbt, Key signerKey, int inputIndex = 0,
                     TaprootSigHash sigHash = TaprootSigHash.Default)
```

**2. TryFinalizePSBT** - Finalize if threshold met
```csharp
public Transaction TryFinalizePSBT(PSBT psbt, int inputIndex = 0, bool useBufferedSize = false)
```
- Returns `Transaction` if k signatures present (broadcast it!)
- Returns `null` if more signatures needed (forward PSBT)

**3. FinalizePSBT** - Force finalization (for advanced use)
```csharp
public Transaction FinalizePSBT(PSBT psbt, int inputIndex = 0, bool useBufferedSize = false)
```
- Throws exception if threshold not met
- Use only when you're certain PSBT is complete

**4. CreatePSBT** - Create PSBT from transaction
```csharp
public PSBT CreatePSBT(Transaction transaction, ICoin[] spentCoins)
```

## The Universal Pattern

Every signer uses this exact same code:

```csharp
// Sign
multiSig.SignPSBT(psbt, myKey);

// Try to finalize
var tx = multiSig.TryFinalizePSBT(psbt);

// Broadcast or forward
if (tx != null)
    rpc.SendRawTransaction(tx);  // Done!
else
    SendToNextSigner(psbt.ToBase64());  // Need more signatures
```

That's it. No counting signatures, no checking state, no coordination logic.

## Complete Example

```csharp
// Create 3-of-5 multisig
var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 3, Network.RegTest);

// Create transaction
var (tx, _) = multiSig.CreateDualTransactions(coin, paymentAddr, amount, changeAddr, feeRate, signerIndices);
var psbt = multiSig.CreatePSBT(tx, new[] { coin });

// ========== SIGNER 0 ==========
multiSig.SignPSBT(psbt, signerKeys[0]);
var finalTx = multiSig.TryFinalizePSBT(psbt);
if (finalTx == null)
{
    var serialized = psbt.ToBase64();
    // Send to signer 2
}

// ========== SIGNER 2 ==========
var psbt2 = PSBT.Parse(serialized, Network.RegTest);
multiSig.SignPSBT(psbt2, signerKeys[2]);
finalTx = multiSig.TryFinalizePSBT(psbt2);
if (finalTx == null)
{
    serialized = psbt2.ToBase64();
    // Send to signer 4
}

// ========== SIGNER 4 ==========
var psbt3 = PSBT.Parse(serialized, Network.RegTest);
multiSig.SignPSBT(psbt3, signerKeys[4]);
finalTx = multiSig.TryFinalizePSBT(psbt3);
if (finalTx != null)
{
    // Success! Broadcast
    var txid = rpc.SendRawTransaction(finalTx);
    Console.WriteLine($"Broadcast! Txid: {txid}");
}
```

## What Was Removed

- ❌ `IsComplete()` - Now private implementation detail
- ❌ Separate threshold checking logic
- ❌ Manual signature counting

## What Remains

- ✅ `SignPSBT()` - Add signature
- ✅ `TryFinalizePSBT()` - Finalize or return null
- ✅ `FinalizePSBT()` - Advanced use (throws if not ready)
- ✅ `CreatePSBT()` - Create from transaction

## Design Rationale

### Why no `IsComplete()`?

Because it creates redundancy:

```csharp
// BAD: Two calls doing the same work
if (multiSig.IsComplete(psbt))  // Counts signatures
{
    var tx = multiSig.FinalizePSBT(psbt);  // Counts signatures again
    Broadcast(tx);
}

// GOOD: One call
var tx = multiSig.TryFinalizePSBT(psbt);  // Counts once
if (tx != null) Broadcast(tx);
```

### Why keep `FinalizePSBT()`?

For cases where you **know** the PSBT is complete and want an exception if it's not:

```csharp
// Collect all signatures first
foreach (var signer in allSigners)
    multiSig.SignPSBT(psbt, signer);

// Now we KNOW it's complete - throw if not
var tx = multiSig.FinalizePSBT(psbt);  // Throws if something went wrong
rpc.SendRawTransaction(tx);
```

But 99% of the time, use `TryFinalizePSBT()`.

## Test Coverage

All workflows tested in `DelegatedMultiSigTests.cs`:

- ✅ `CanUsePSBTWorkflow` - Basic PSBT usage
- ✅ `DualBufferProgressiveSigning_3of5_PSBT` - Multiple transactions
- ✅ `PSBT_BIP174_Compliance_Test` - BIP 174 compliance
- ✅ `PSBT_SimplifiedWorkflow_AutoFinalize` - Simplified API pattern

All tests pass with real Bitcoin RegTest network validation.

## Summary

**The API is now as simple as possible:**

1. Sign: `SignPSBT()`
2. Try finalize: `TryFinalizePSBT()`
3. If transaction → broadcast
4. If null → forward

No manual checking, no coordination logic, no redundant calls.
