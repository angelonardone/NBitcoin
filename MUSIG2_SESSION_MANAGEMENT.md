# MuSig2 Session Management Design

## Problem Statement

DelegatedMultiSig2 uses MuSig2 (interactive Schnorr signature aggregation), which requires **stateful multi-round protocol**:

### MuSig2 Protocol Rounds
```
Round 1: Generate nonces → Store private nonces
Round 2: Exchange public nonces → Aggregate
Round 3: Sign using stored nonces → Produce signatures
```

### Current Issues

**Without session management:**
❌ State stored only in `MuSig2SignatureBuilder` instance
❌ User must keep builder instance alive between rounds
❌ Multiple concurrent signings can interfere
❌ No isolation between different signing operations
❌ Application restart = lost state = cannot complete signing
❌ **CRITICAL**: No nonce reuse protection across restarts

### Why This Matters

**Nonce reuse = private key leak!**
If the same nonce is used to sign two different messages, an attacker can extract your private key.

## Solution: In-Memory Session Manager

### Design Principles

1. ✅ **Isolation**: Each signing operation gets unique session ID
2. ✅ **Thread-safe**: Lock-based synchronization
3. ✅ **Auto-cleanup**: Sessions expire after 1 hour of inactivity
4. ✅ **Nonce safety**: Nonces disposed when session closes
5. ❌ **No persistence**: All state lost on restart (by design)

### Implementation

```csharp
/// <summary>
/// In-memory session manager for MuSig2 signing.
/// Provides isolation between concurrent signing sessions.
/// </summary>
private static class MuSig2SessionManager
{
    private static readonly object _lock = new object();
    private static readonly Dictionary<string, MuSig2SessionState> _sessions;
    private static readonly TimeSpan _sessionTimeout = TimeSpan.FromHours(1);

    public static string CreateSession(DelegatedMultiSig2 multiSig, Transaction tx, ICoin[] coins)
    {
        lock (_lock)
        {
            var sessionId = Guid.NewGuid().ToString();
            var state = new MuSig2SessionState
            {
                SessionId = sessionId,
                MultiSig = multiSig,
                Transaction = tx,
                SpentCoins = coins,
                Created = DateTime.UtcNow,
                LastAccessed = DateTime.UtcNow,
                NonceExchanges = new Dictionary<...>(),
                PrivateNonces = new Dictionary<...>(),  // ← Critical state
                PartialSignatures = new Dictionary<...>(),
                SigHashUsed = new Dictionary<...>()
            };
            _sessions[sessionId] = state;
            return sessionId;
        }
    }

    public static void CloseSession(string sessionId)
    {
        lock (_lock)
        {
            if (_sessions.TryGetValue(sessionId, out var state))
            {
                // IMPORTANT: Dispose private nonces to prevent reuse
                foreach (var inputNonces in state.PrivateNonces.Values)
                {
                    foreach (var nonce in inputNonces.Values)
                    {
                        nonce?.Dispose();  // ← Secure cleanup
                    }
                }
                _sessions.Remove(sessionId);
            }
        }
    }
}

private class MuSig2SessionState
{
    public string SessionId { get; set; }
    public DelegatedMultiSig2 MultiSig { get; set; }
    public Transaction Transaction { get; set; }
    public ICoin[] SpentCoins { get; set; }
    public DateTime Created { get; set; }
    public DateTime LastAccessed { get; set; }

    // MuSig2 state
    public Dictionary<int, Dictionary<int, MuSig2NonceExchange>> NonceExchanges { get; set; }
    public Dictionary<int, Dictionary<int, MusigPrivNonce>> PrivateNonces { get; set; }
    public Dictionary<int, Dictionary<int, MusigPartialSignature>> PartialSignatures { get; set; }
    public Dictionary<int, TaprootSigHash> SigHashUsed { get; set; }
}
```

### Session-Based API

#### Old Way (Manual State Management)
```csharp
// ❌ User must manually manage builder instance between rounds
var builder = multiSig.CreateSignatureBuilder(tx, coins);

// Round 1: Generate nonces
var myNonces = builder.GenerateNonce(myKey, 0);
// ... must keep 'builder' instance alive ...

// Round 2: Add others' nonces (time passes, maybe in different method/request)
builder.AddNonces(0, otherNonces);  // ← Requires same builder instance!

// Round 3: Sign
builder.SignWithSigner(myKey, 0);

// Problem: What if app restarts between rounds? All state lost!
```

#### New Way (Session-Based)
```csharp
// ✅ Create session - get ID
var sessionId = multiSig.CreateSigningSession(tx, coins);

// Round 1: Generate nonces
var myNonces = multiSig.GenerateNoncesForSession(sessionId, myKey, 0);
// sessionId can be stored in DB, passed between requests, etc.

// ... time passes, maybe different process/request ...

// Round 2: Add others' nonces
multiSig.AddNoncesToSession(sessionId, 0, otherNonces);

// Round 3: Sign
multiSig.SignInSession(sessionId, myKey, 0);

// Finalize
var finalTx = multiSig.TryFinalizeSession(sessionId, 0);

// Cleanup
multiSig.CloseSession(sessionId);

// Benefits:
// ✅ State isolated by session ID
// ✅ Can have multiple concurrent signings
// ✅ sessionId is just a string - easy to store/pass around
```

### Complete API

```csharp
public class DelegatedMultiSig2
{
    // Create a new signing session
    public string CreateSigningSession(Transaction tx, ICoin[] coins);

    // Round 1: Generate and store nonces
    public MuSig2NonceData GenerateNoncesForSession(
        string sessionId, Key signerKey, int inputIndex,
        TaprootSigHash sigHash = TaprootSigHash.Default);

    // Round 2: Add received nonces
    public void AddNoncesToSession(
        string sessionId, int inputIndex, MuSig2NonceData nonceData);

    // Round 3: Sign using stored nonces
    public MuSig2SignatureData SignInSession(
        string sessionId, Key signerKey, int inputIndex,
        TaprootSigHash sigHash = TaprootSigHash.Default);

    // Try to finalize (returns null if need more signatures)
    public Transaction TryFinalizeSession(string sessionId, int inputIndex);

    // Clean up session
    public void CloseSession(string sessionId);

    // Monitoring
    public static int GetActiveSessionCount();
}
```

## Usage Example

### Scenario: Web API with Multiple Users

```csharp
// Controller 1: User initiates signing
[HttpPost("/api/musig2/initiate")]
public IActionResult InitiateSigning(InitiateRequest req)
{
    var tx = CreateTransaction(req.Inputs, req.Outputs);
    var coins = GetCoins(req.Inputs);

    // Create session
    var sessionId = multiSig.CreateSigningSession(tx, coins);

    // Generate my nonces
    var myNonces = multiSig.GenerateNoncesForSession(
        sessionId, myPrivateKey, 0);

    // Store session ID in database
    await db.SaveSession(new SigningSession
    {
        SessionId = sessionId,
        UserId = req.UserId,
        Status = "AwaitingNonces",
        MyNonces = myNonces.Serialize()
    });

    return Ok(new { sessionId, nonces = myNonces.Serialize() });
}

// Controller 2: Receive nonces from other signers
[HttpPost("/api/musig2/add-nonces")]
public IActionResult AddNonces(AddNoncesRequest req)
{
    // Session ID stored in DB, retrieve it
    var session = await db.GetSession(req.SessionId);

    // Add received nonces
    multiSig.AddNoncesToSession(
        req.SessionId, 0,
        MuSig2NonceData.Deserialize(req.NonceData));

    // Update status
    session.Status = "NoncesComplete";
    await db.SaveSession(session);

    return Ok();
}

// Controller 3: Sign
[HttpPost("/api/musig2/sign")]
public IActionResult Sign(SignRequest req)
{
    var session = await db.GetSession(req.SessionId);

    // Sign using session state
    var signature = multiSig.SignInSession(
        req.SessionId, myPrivateKey, 0);

    // Try to finalize
    var finalTx = multiSig.TryFinalizeSession(req.SessionId, 0);

    if (finalTx != null)
    {
        // All signatures collected!
        await BroadcastTransaction(finalTx);
        multiSig.CloseSession(req.SessionId);  // Cleanup
        return Ok(new { txid = finalTx.GetHash().ToString() });
    }

    return Ok(new { status = "AwaitingMoreSignatures" });
}
```

## Concurrent Sessions Example

```csharp
// User signing multiple transactions simultaneously
var session1 = multiSig.CreateSigningSession(tx1, coins1);
var session2 = multiSig.CreateSigningSession(tx2, coins2);
var session3 = multiSig.CreateSigningSession(tx3, coins3);

// Generate nonces for all sessions
var nonces1 = multiSig.GenerateNoncesForSession(session1, myKey, 0);
var nonces2 = multiSig.GenerateNoncesForSession(session2, myKey, 0);
var nonces3 = multiSig.GenerateNoncesForSession(session3, myKey, 0);

// Sessions are completely isolated - no interference
// Each has its own nonces, state, signatures

// Sign them independently
multiSig.SignInSession(session1, myKey, 0);
multiSig.SignInSession(session2, myKey, 0);
multiSig.SignInSession(session3, myKey, 0);

// Finalize independently
var finalTx1 = multiSig.TryFinalizeSession(session1, 0);
var finalTx2 = multiSig.TryFinalizeSession(session2, 0);
var finalTx3 = multiSig.TryFinalizeSession(session3, 0);

// Cleanup
multiSig.CloseSession(session1);
multiSig.CloseSession(session2);
multiSig.CloseSession(session3);
```

## Security Features

### 1. Nonce Disposal
```csharp
public static void CloseSession(string sessionId)
{
    // Dispose private nonces to prevent reuse
    foreach (var nonce in state.PrivateNonces.Values)
    {
        nonce?.Dispose();  // ← Clears sensitive data from memory
    }
}
```

### 2. Automatic Expiration
```csharp
// Sessions expire after 1 hour of inactivity
private static readonly TimeSpan _sessionTimeout = TimeSpan.FromHours(1);

// Prevents abandoned sessions from consuming memory forever
private static void CleanupExpiredSessions()
{
    var expired = _sessions
        .Where(kvp => now - kvp.Value.LastAccessed > _sessionTimeout)
        .Select(kvp => kvp.Key)
        .ToList();

    foreach (var id in expired)
        CloseSession(id);  // ← Proper cleanup with nonce disposal
}
```

### 3. Thread Safety
```csharp
private static readonly object _lock = new object();

public static string CreateSession(...)
{
    lock (_lock)  // ← Prevents race conditions
    {
        // Thread-safe session creation
    }
}
```

## Implementation Status

**Current Status**: ⏸️ **PENDING - Design Complete, Implementation Deferred**

**What's Implemented**:
1. ✅ `MuSig2SessionManager` static class (internal structure only)
2. ✅ `MuSig2SessionState` class (internal structure only)
3. ✅ Simulation tests demonstrating the concept (`MuSig2SessionSimulationTest.cs`)

**What's NOT Implemented** (Pending):
1. ❌ Public session-based API methods on `DelegatedMultiSig2` class
   - `CreateSigningSession()`
   - `GenerateNoncesForSession()`
   - `AddNoncesToSession()`
   - `SignInSession()`
   - `TryFinalizeSession()`
   - `CloseSession()`
   - `GetActiveSessionCount()`

**Why Implementation is Deferred**:

The session-based API is designed for **concurrent, multi-threaded, or distributed scenarios** such as:
- Web APIs where signing happens across multiple HTTP requests
- Multi-process applications
- Concurrent signing of multiple transactions

However, the **current use cases in NBitcoin are single-threaded unit tests** where:
- Each test runs in isolation
- The `MuSig2SignatureBuilder` instance stays in scope throughout the signing process
- No concurrent signing operations occur
- Tests complete in milliseconds

**Decision**: Since there's no immediate need for session management in the existing codebase, the public API implementation is **deferred** until:
1. Real-world use case emerges (web API, multi-process app, etc.)
2. User explicitly requests concurrent signing support
3. Performance testing shows builder instance management is problematic

The existing `CreateSignatureBuilder()` API remains the recommended approach for simple, single-threaded scenarios.

**Backward Compatibility** (When Implemented):
- ✅ Existing `CreateSignatureBuilder()` API will continue to work
- ✅ New session-based API will be additive
- ✅ No breaking changes planned

## Summary

**Design Complete, Implementation Pending**

In-memory session management **would solve** the MuSig2 stateful protocol problem for concurrent/distributed scenarios:
- ✅ **Isolation**: Multiple concurrent signings don't interfere
- ✅ **Safety**: Proper nonce disposal prevents reuse
- ✅ **Simplicity**: Session ID is just a string
- ✅ **Flexibility**: Works with web apps, multi-process, etc.
- ❌ **No persistence**: Restart = start over (acceptable trade-off)

**Current Recommendation**:
- For **single-threaded applications** (like current NBitcoin tests): Use `CreateSignatureBuilder()` - simpler and sufficient
- For **concurrent/distributed applications**: Session-based API should be implemented when needed

The design is complete and tested via simulations. Implementation is deferred until a real-world use case emerges.
