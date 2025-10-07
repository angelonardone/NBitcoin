# Simplified PSBT Workflow

## Overview

The PSBT workflow is now maximally simple. Each signer:

1. Signs the PSBT
2. Tries to finalize
3. If it returns a transaction → broadcast
4. If it returns null → forward to next signer

## API

### SignPSBT()
Adds your signature to the PSBT:

```csharp
public PSBT SignPSBT(PSBT psbt, Key signerKey, int inputIndex = 0,
                     TaprootSigHash sigHash = TaprootSigHash.Default)
```

**Returns:** The modified PSBT with your signature added

### TryFinalizePSBT()
Checks if threshold is met and finalizes if ready:

```csharp
public Transaction TryFinalizePSBT(PSBT psbt, int inputIndex = 0, bool useBufferedSize = false)
```

**Returns:**
- `Transaction` if PSBT has k signatures (ready to broadcast)
- `null` if more signatures needed (forward PSBT to next signer)

**Note:** This method internally checks if the threshold is met. No need for a separate `IsComplete()` check!

## Simplified Workflow Example

```csharp
// Each signer follows this pattern:
multiSig.SignPSBT(psbt, myKey);

var finalTx = multiSig.TryFinalizePSBT(psbt);
if (finalTx != null)
{
    // Threshold met - broadcast!
    rpc.SendRawTransaction(finalTx);
}
else
{
    // Need more signatures - forward to next signer
    SendToNextSigner(psbt.ToBase64());
}
```

## Complete Example: 3-of-5 Multisig

```csharp
// Setup
var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 3, Network.RegTest);
var (tx, _) = multiSig.CreateDualTransactions(coin, paymentAddr, amount, changeAddr, feeRate, signerIndices);
var psbt = multiSig.CreatePSBT(tx, new[] { coin });

// Signer 0
multiSig.SignPSBT(psbt, signerKeys[0]);
var finalTx = multiSig.TryFinalizePSBT(psbt);
if (finalTx == null)
{
    // Not ready - forward to signer 2
    var serialized = psbt.ToBase64();
    // ... send to signer 2 ...
}

// Signer 2 receives
var psbt2 = PSBT.Parse(serialized, Network.RegTest);
multiSig.SignPSBT(psbt2, signerKeys[2]);
finalTx = multiSig.TryFinalizePSBT(psbt2);
if (finalTx == null)
{
    // Still not ready - forward to signer 4
    serialized = psbt2.ToBase64();
    // ... send to signer 4 ...
}

// Signer 4 receives
var psbt3 = PSBT.Parse(serialized, Network.RegTest);
multiSig.SignPSBT(psbt3, signerKeys[4]);
finalTx = multiSig.TryFinalizePSBT(psbt3);
if (finalTx != null)
{
    // Threshold met! Broadcast
    var txid = rpc.SendRawTransaction(finalTx);
    Console.WriteLine($"Success! Txid: {txid}");
}
```

## Why This Is Better

### Before: Multiple Methods
```csharp
// Option 1: Manual check
multiSig.SignPSBT(psbt, key);
if (multiSig.IsComplete(psbt))
{
    var tx = multiSig.FinalizePSBT(psbt);
    rpc.SendRawTransaction(tx);
}
else
{
    SendToNextSigner(psbt);
}

// Option 2: Separate calls
multiSig.SignPSBT(psbt, key);
var tx = multiSig.FinalizePSBT(psbt);  // Might throw!
rpc.SendRawTransaction(tx);
```

**Problems:**
- `IsComplete()` + `FinalizePSBT()` = redundant
- Need to know when to call which method
- Extra API surface

### After: Single Method
```csharp
multiSig.SignPSBT(psbt, key);
var tx = multiSig.TryFinalizePSBT(psbt);
if (tx != null)
    rpc.SendRawTransaction(tx);
else
    SendToNextSigner(psbt);
```

**Benefits:**
- One method does everything
- Returns transaction or null (clear contract)
- Impossible to misuse
- Minimal API surface

## Test Results

Test: `PSBT_SimplifiedWorkflow_AutoFinalize` demonstrates this pattern:

```
=== Simplified PSBT Workflow with Auto-Finalization ===
Demonstrating: Sign → Check if complete → Finalize or Forward
📋 Created 3-of-5 multisig

👤 Signer #0: Signing and checking...
   ✗ Not enough signatures yet (need 3, have 1)
   → Forwarding PSBT to next signer

👤 Signer #2: Signing and checking...
   ✗ Not enough signatures yet (need 3, have 2)
   → Forwarding PSBT to next signer

👤 Signer #4: Signing and checking...
   ✓ Threshold met! (need 3, have 3)
   ✓ Transaction finalized automatically

📡 Broadcasting transaction...
   ✅ Transaction accepted! Txid: ab8d173b...

✅ SUCCESS: Simplified workflow demonstrated!
   • Each signer: Sign → Check → Finalize or Forward
   • No manual coordination needed
   • Automatic finalization when threshold met
```

## API Summary

| Method | Purpose | Returns |
|--------|---------|---------|
| `SignPSBT()` | Add your signature to PSBT | Modified PSBT |
| `TryFinalizePSBT()` | Check threshold and finalize if ready | Transaction or null |
| `FinalizePSBT()` | Force finalization (throws if not ready) | Transaction |

## The Pattern

**Always use this pattern:**

```csharp
multiSig.SignPSBT(psbt, myKey);
var tx = multiSig.TryFinalizePSBT(psbt);
if (tx != null)
    Broadcast(tx);
else
    ForwardToNextSigner(psbt);
```

**Notes:**
- `TryFinalizePSBT()` handles everything - checking threshold and finalizing
- No need for `IsComplete()` - it's now a private implementation detail
- Only use `FinalizePSBT()` directly if you're certain the PSBT is complete and want an exception if it's not
