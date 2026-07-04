# AES-GCM Nonce Construction Paradigms and Collision Analysis

This repository provides a Java implementation demonstrating secure Nonce (Initialization Vector) management strategies for **AES-GCM** encryption. Because GCM can be fundamentally broken if a key/nonce pair is ever reused ("Forbidden Attack"), this project explores, benchmarks, and validates two distinct architectural approaches to safe nonce generation.

### Implementations

1. **GCMEncryption Class (Nonce Strategies):**
   * **Deterministic Approach:** Constructs a 12-byte (96-bit) IV by combining a static 4-byte `Device ID` with an incrementing 8-byte persistent counter. This guarantees absolute uniqueness across a single device's lifecycle.
   * **Hybrid Randomized Approach:** Combines a 4-byte `Device ID` with an 8-byte cryptographically secure random segment (`SecureRandom`). It dynamically applies a bitwise XOR operation against an atomic message counter to prevent birthday attack collisions during long-lived cryptographic sessions.

2. **NonceCollisionTest Class:**
   * A verification script that simulates the generation of 100,000 random 96-bit GCM nonces. 
   * Tracks distribution states using a high-performance hash set to test collision boundaries and demonstrate statistical safety against the Birthday Paradox.

### ⚙️ Cryptographic specifications
* **Cipher Suite:** `AES/GCM/NoPadding`
* **Key Length:** 256-bit AES
* **IV/Nonce Length:** 12 bytes (96 bits)
* **Authentication Tag Length:** 128 bits
