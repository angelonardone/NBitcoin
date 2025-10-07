# Multi-Path Progressive PSBT Workflow - CORRECT Implementation

## The Problem (What Was Wrong Before)

The initial fix created **ONE transaction with MAXIMUM fee** to cover all possible signing paths. This was wasteful because:

❌ If the cheapest path needs 180 vbytes but the most expensive needs 220 vbytes
❌ We paid for 220 vbytes even if the cheapest signers participated
❌ Result: **Wasted fees** on every transaction

## The Correct Solution

Create **MULTIPLE transactions** - one for each possible signing path, each with its **optimal fee**.

### How It Works

```
3-of-5 Multisig, Signer #0 wants to initiate

Step 1: First Signer Creates Multiple Transactions
┌─────────────────────────────────────────────────────┐
│ Signer #0 participates in 6 script paths (C(4,2))  │
│                                                     │
│ Transaction 1: Signers [0,1,2] → Fee: 11,050 sats │
│ Transaction 2: Signers [0,1,3] → Fee: 11,100 sats │
│ Transaction 3: Signers [0,1,4] → Fee: 11,150 sats │
│ Transaction 4: Signers [0,2,3] → Fee: 11,200 sats │
│ Transaction 5: Signers [0,2,4] → Fee: 11,250 sats │
│ Transaction 6: Signers [0,3,4] → Fee: 11,300 sats │
│                                                     │
│ ✅ Signs all 6 transactions                        │
│ ✅ Broadcasts MultiPathPSBT to ALL potential       │
│    signers (#1, #2, #3, #4)                       │
└─────────────────────────────────────────────────────┘

Step 2: Signer #2 Receives and Signs
┌─────────────────────────────────────────────────────┐
│ Filters to paths where #2 participates:           │
│                                                     │
│ ✅ Transaction 1: [0,1,2] - #2 participates       │
│ ❌ Transaction 2: [0,1,3] - #2 NOT in this path   │
│ ❌ Transaction 3: [0,1,4] - #2 NOT in this path   │
│ ✅ Transaction 4: [0,2,3] - #2 participates       │
│ ✅ Transaction 5: [0,2,4] - #2 participates       │
│ ❌ Transaction 6: [0,3,4] - #2 NOT in this path   │
│                                                     │
│ Signs transactions 1, 4, 5                         │
│ Broadcasts 3 remaining paths to others             │
└─────────────────────────────────────────────────────┘

Step 3: Signer #4 Receives and Signs
┌─────────────────────────────────────────────────────┐
│ Filters to paths where #4 participates:           │
│                                                     │
│ ❌ Transaction 1: [0,1,2] - #4 NOT in this path   │
│ ❌ Transaction 4: [0,2,3] - #4 NOT in this path   │
│ ✅ Transaction 5: [0,2,4] - #4 participates       │
│                                                     │
│ Only 1 path remains!                               │
│ Signs transaction 5                                │
│                                                     │
│ Now we have k=3 signatures: #0, #2, #4            │
│ Fee: 11,250 sats (EXACT for this combination)     │
│                                                     │
│ ✅ FINALIZES and broadcasts transaction 5         │
└─────────────────────────────────────────────────────┘
```

## Key Benefits

✅ **No wasted fees**: Each transaction has exact fee for its signer combination
✅ **Progressive narrowing**: Paths naturally filter down as signers participate
✅ **Cheapest path wins**: Final signer gets the cheapest complete transaction
✅ **No coordination needed**: First signer doesn't need to know who will sign

## Implementation

### MultiPathPSBT Class

```csharp
public class MultiPathPSBT
{
    // Holds multiple PSBTs, one per signing path
    private List<(int scriptIndex, int[] signerIndices, PSBT psbt, int virtualSize)> _paths;

    // Tracks which signers have participated
    private HashSet<int> _currentSigners;

    // Add a signer - automatically filters to viable paths
    public MultiPathPSBT AddSigner(Key signerKey);

    // Try to finalize - returns CHEAPEST complete transaction
    public Transaction TryFinalize();

    // Serialize/deserialize for transmission
    public string Serialize();
    public static MultiPathPSBT Deserialize(string data);
}
```

### Usage

```csharp
// First signer creates multi-path PSBT
var multiPathPSBT = multiSig.CreateMultiPathPSBTForFirstSigner(
    signerKeys[0],
    coin,
    paymentAddress,
    paymentAmount,
    changeAddress,
    feeRate,
    bufferPercentage: 15.0);

Console.WriteLine($"Created {multiPathPSBT.PathCount} separate transactions");

// Serialize and send to all potential signers
var serialized = multiPathPSBT.Serialize();

// Signer #2 receives and signs
var received = MultiPathPSBT.Deserialize(serialized, network);
var afterSign = received.AddSigner(multiSig, signerKeys[2]);
Console.WriteLine($"Narrowed from {received.PathCount} to {afterSign.PathCount} paths");

// Continue until threshold met
var finalTx = afterSign.TryFinalize(multiSig);
if (finalTx != null)
{
    // Chose cheapest complete path - broadcast it!
    rpc.SendRawTransaction(finalTx);
}
```

## Test Results

```
=== Correct Multi-Path Progressive PSBT Workflow ===
📋 Created 3-of-5 multisig
   • Total possible 3-signer combinations: 10

👤 Signer #0: Creating multi-path PSBT...
   • Created 6 separate transactions
   • All signed by signer #0

👤 Signer #2: Receives multi-path PSBT and signs...
   • Narrowed from 6 to 3 viable paths

👤 Signer #4: Receives multi-path PSBT and signs...
   • Narrowed from 3 to 1 viable path(s)
   ✓ Chose CHEAPEST complete transaction path
   ✓ Fee is EXACT - not wasted

✅ Transaction accepted!

✅ SUCCESS: Multi-path progressive workflow demonstrated!
   • First signer: Creates MULTIPLE transactions (one per path)
   • Each transaction: Optimal fee for that specific signer combination
   • Progressive narrowing: 10 paths → 3 paths → 1 path
   • Final signer: Chose CHEAPEST complete transaction
   • NO WASTED FEES - exact fee for actual participants
```

## Fee Comparison

### Wrong Approach (Single Transaction with MAX fee):
```
All paths need: 180-220 vbytes
We create ONE transaction with: 220 vbytes (worst case)
If cheapest signers (#0, #1, #2) participate: 180 vbytes needed
Result: Paid 220 vbytes = WASTED 40 vbytes worth of fees
```

### Correct Approach (Multiple Transactions):
```
Create 10 transactions:
  Path [0,1,2]: 180 vbytes → Fee: 9,000 sats
  Path [0,1,3]: 185 vbytes → Fee: 9,250 sats
  Path [0,1,4]: 190 vbytes → Fee: 9,500 sats
  ...
  Path [2,3,4]: 220 vbytes → Fee: 11,000 sats

If signers #0, #1, #2 participate:
  → Use transaction for [0,1,2]
  → Pay EXACTLY 9,000 sats
  → NO WASTE!
```

## When to Use

### Use `CreateMultiPathPSBTForFirstSigner`:
✅ First signer doesn't know who will participate
✅ Want optimal (minimum) fees
✅ Progressive PSBT workflow with multiple rounds
✅ Broadcasting to all potential signers

### Use `CreateDualTransactions`:
✅ You already know the exact k signers upfront
✅ Need base + buffered fee variants
✅ Testing specific signer combinations

## Summary

The multi-path approach ensures **NO WASTED FEES** by creating separate transactions for each possible signer combination, each with its exact optimal fee. As signers participate, paths naturally narrow down, and the final signer chooses the cheapest complete transaction. This is the correct way to implement progressive PSBT signing when you don't know participants upfront.
