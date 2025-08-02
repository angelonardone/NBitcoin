# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Building the Project
```bash
# Clean and build the main library
dotnet clean -c Release
dotnet build -c Release

# Build specific project
dotnet build ./NBitcoin/NBitcoin.csproj -c Release

# Build for specific framework
dotnet build ./NBitcoin/NBitcoin.csproj -c Release -f net6.0
```

### Running Tests
```bash
# Run all tests for .NET 6.0
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
dotnet test ./NBitcoin.Tests/NBitcoin.Tests.csproj -c Release -f net6.0 \
    --filter "RestClient=RestClient|RPCClient=RPCClient|Protocol=Protocol|Core=Core|UnitTest=UnitTest|Altcoins=Altcoins|PropertyTest=PropertyTest" \
    -p:ParallelizeTestCollections=false

# Run specific test category
dotnet test ./NBitcoin.Tests/NBitcoin.Tests.csproj -c Release -f net6.0 --filter "Core=Core"

# Run a single test
dotnet test ./NBitcoin.Tests/NBitcoin.Tests.csproj -c Release -f net6.0 --filter "FullyQualifiedName~TestName"
```

### Environment Setup
```bash
# Install required .NET SDK
./Build/CI/install-env.sh

# Clear NuGet cache if needed
dotnet nuget locals all --clear
```

## High-Level Architecture

### Core Design Principles
- **Type Safety**: Strongly-typed APIs throughout, avoiding string-based interfaces
- **Immutability**: Core types are immutable for thread safety
- **Bitcoin Core Compatibility**: Bug-for-bug compatibility where necessary
- **Extensibility**: Multiple extension points for custom implementations

### Key Architectural Components

#### 1. Protocol Primitives
- **Transaction/Block**: Core blockchain data structures in root namespace
- **Script**: Full script interpreter with evaluation engine
- **Key/PubKey**: Cryptographic primitives with comprehensive signing support
- **Address Types**: BitcoinAddress, BitcoinSegwitAddress, TaprootAddress hierarchies

#### 2. Network Architecture
- **Network Class**: Encapsulates all chain-specific parameters (genesis, ports, seeds)
- **ConsensusFactory**: Factory pattern for creating network-specific objects
- **Protocol Namespace**: P2P networking implementation with Node, NodeServer classes

#### 3. Transaction Building
- **TransactionBuilder**: Fluent API for constructing transactions
- **BuilderExtensions**: Extensible system for custom script types
- **Coin Selection**: Strategy pattern with ICoinSelector interface

#### 4. Serialization System
- **BitcoinStream**: Bidirectional serialization with network byte order
- **IBitcoinSerializable**: Core interface for all protocol objects
- **ConsensusFactory**: Handles version-specific serialization

#### 5. Modern Features
- **PSBT (BIP174/370)**: Full support in BIP174/ and BIP370/ namespaces
- **Output Descriptors**: In Scripting/ namespace with parser
- **Taproot**: Complete BIP340/341/342 implementation
- **Miniscript**: WalletPolicies/ namespace

#### 6. Cryptography
- **NBitcoin.Secp256k1**: Managed C# implementation of secp256k1
- **Supports**: ECDSA, Schnorr, MuSig, adaptor signatures
- **No Native Dependencies**: Pure managed code

#### 7. Altcoin Support
- **NBitcoin.Altcoins**: Separate project for altcoin networks
- **Extension Pattern**: Altcoins extend NetworkSetBase
- **Custom Consensus**: Override ConsensusFactory for protocol differences

### Important Patterns

#### Factory Pattern
```csharp
// ConsensusFactory creates network-specific implementations
var tx = network.Consensus.ConsensusFactory.CreateTransaction();
```

#### Builder Pattern
```csharp
// TransactionBuilder provides fluent transaction construction
var tx = builder
    .AddCoins(coins)
    .Send(destination, amount)
    .SetChange(changeAddress)
    .SendFees(fee)
    .BuildTransaction(true);
```

#### Network Configuration
```csharp
// Networks are configured through NetworkBuilder
var builder = new NetworkBuilder()
    .SetConsensus(new Consensus())
    .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 0x00 })
    .SetPort(8333);
```

### Key Interfaces
- **IBitcoinSerializable**: Base for all serializable objects
- **IDestination**: Anything that can receive bitcoins
- **ITransactionRepository**: Transaction storage abstraction
- **ICoinSelector**: Coin selection strategy
- **IHDKey**: Hierarchical deterministic key abstraction

### Testing Approach
- Comprehensive unit tests ported from Bitcoin Core
- Property-based testing with FsCheck
- Test data in NBitcoin.Tests/data/ directory
- Network isolation through TestFramework project

### Common Development Tasks

#### Adding New Address Type
1. Extend BitcoinAddress base class
2. Implement GetScriptPubKey() method
3. Add parsing support in Network class
4. Update BitcoinAddress.Create() factory

#### Supporting New Network
1. Create Network instance with NetworkBuilder
2. Override ConsensusFactory if protocol differs
3. Add to appropriate NetworkSet
4. Register in Network.Register()

#### Implementing Custom Script
1. Create BuilderExtension subclass
2. Override CanCombineScriptSig/CanEstimateScriptSigSize
3. Implement CombineScriptSig/EstimateScriptSigSize
4. Add to TransactionBuilder.StandardScripts

This architecture enables NBitcoin to provide comprehensive Bitcoin functionality while remaining extensible for altcoins and custom use cases.

## Advanced Multisig Implementations

NBitcoin includes several advanced multisig implementations that extend beyond traditional limitations:

### DelegatedMultiSig Family
- **DelegatedMultiSig**: Taproot-based multisig using script combinations for optimal k-of-n scenarios
- **DelegatedMultiSig2**: MuSig2 implementation with interactive Schnorr signature aggregation
- **SegWitMultiSig**: Traditional SegWit P2SH-P2WSH multisig for up to 16 participants (clean, reliable implementation)

### SegWitMultiSig Key Features
```csharp
// Create 2-of-3 multisig using standard OP_CHECKMULTISIG
var multiSig = new SegWitMultiSig(signerPubKeys, 2, Network.RegTest);

// Uses standard OP_CHECKMULTISIG (≤16 participants)
// Traditional SegWit P2SH-P2WSH structure
// Clean integration with NBitcoin's TransactionBuilder
```

### Multisig Comparison Testing
The codebase includes comprehensive testing applications:
- `QuickMultisigExecutorDemo.cs`: Configuration testing across all multisig types
- `SegWitMultiSigTests.cs`: Comprehensive test suite for SegWit multisig
- Actual blockchain transaction verification and size measurement