# Schnorr Identification Protocol (Zero Knowledge Proof)

🇮🇹 - [Leggi in Italiano](./README_it.md)

## Introduction
This project is an implementation of the Schnorr identification protocol, a classic example of a Zero-Knowledge Proof of Knowledge (ZKPoK).
It demonstrates how a prover can convince a verifier of knowing a secret $x$ such that $y = g^x mod (p)$, without revealing $x$ itself.

This project was developed as part of the Information Security M (Sicurezza dell'Informazione M) course of University of Bologna to demonstrate the implementation of a Zero-Knowledge Proof protocol in Java.

## Background & Theory

Zero-Knowledge Proofs (ZKPs) allow one party (the Prover) to convince another party (the Verifier) that they know a certain secret,without revealing any information about the secret itself.

The Schnorr protocol, proposed by Claus-Peter Schnorr (1990), is one of the foundational examples of ZKPs.
It is based on the hardness of the Discrete Logarithm Problem (DLP) in modular arithmetic groups, meaning that, given $p$, $g$, and $y = g^x mod (p)$, it is computationally infeasible to recover $x$.

The protocol achieves three properties:
- **Completeness**: honest provers always convince honest verifiers.
- **Soundness**: dishonest provers cannot convince the verifier without knowing x.
- **Zero-Knowledge**: the verifier learns nothing about x beyond the fact that the prover knows it.

## Project Structure
| Package | Description                                             |
| ------- | ------------------------------------------------------- |
| `model` | Data structures (`Parameters`, `KeyPair`, `Proof`)      |
| `core`  | Core protocol logic (`Prover`, `Verifier`, `Simulator`) |
| `util`  | Cryptographic utilities (randomness, helpers)           |
| `app`   | Demo entry point (`Main.java`)                          |
| `test`  | JUnit test suite (soundness, forgery tests)             |

## Protocol steps
**Setup**: public parameters ($p$, $q$, $g$) define a subgroup of $ℤ^*_p$ of order $q$.

**Key Generation**:

- Private key: $x ∈ Z_q$
- Public key: $y = g^x mod (p)$

**Identification Round**:

- The Prover picks a random $k$, sends $r = g^k mod (p)$.
- The Verifier sends a random challenge $c$.
- The Prover responds with $s = (k + c\cdot x) mod (q)$.
- The Verifier checks if $g^s ≡ r\cdot y^c mod (p)$.

If the equality holds, the verifier is convinced that the prover knows $x$.

## Implementation Overview

This section documents the core classes and methods of the implementation, highlighting how each part contributes to the Schnorr identification protocol.

### ```Parameters.java```

Defines the public parameters ($𝑝$, $𝑞$, $𝑔$) of the protocol.

- ```generate(int bits)```: securely generates a valid set of parameters. Ensures q ∣ (p−1) and that g has exact order q.
- ```demo()```: returns small, human-readable values (unsafe, used for testing).
- ```randomZq()```: produces a random value uniformly distributed in $Z_q$. These parameters define the algebraic group where all operations occur.

### ```KeyPair.java```
Represents the prover’s secret/public key pair ($x$, $y=g^x mod(p)$).
The secret key $x$ is stored as a ```byte[]``` and converted to ```BigInteger``` only when needed.

- ```multiplySecret(BigInteger value)```: computes $(x * value) mod (q)$ without exposing $x$.
- ```matchesSecret(BigInteger candidate)```: allows testing whether a candidate equals the internal private key (used in soundness tests).

No public getter for the private key exists; it remains isolated in this class.

### ```Prover.java```

Handles the prover’s side of the protocol:

- ```generateCommitment()```: samples a random nonce $k$ and computes $r=g^k mod(p)$.
- ```respondToChallenge(BigInteger c)```: computes $s=(k+c \cdot x) mod(q)$, then builds a ```Proof(r, c, s)```.

The internal nonce $k$ is refreshed per execution and never reused.

Together, these methods produce the proof of knowledge transcript sent to the verifier.

### ```Verifier.java```

Implements the verification check:

- ```generateChallenge()```: samples a random challenge $c ∈ Z_q$.
- ```verify(Proof proof, BigInteger publicKey)```: verifies $g^s ≡ r \cdot y^c mod(p)$. Returns ```true``` if the proof is valid, ```false``` otherwise.

A valid proof ensures that the prover must know the secret key $x$ corresponding to the given public key $y$.

### ```Simulator.java```

Used to illustrate zero-knowledge:

- ```simulateProof()```: generates a fake but valid-looking transcript ($r$, $c$, $s$) without using any private key. This shows that the verifier cannot distinguish simulated proofs from genuine ones, demonstrating the zero-knowledge property.

### ```Proof.java```

A simple immutable data class holding:
- ```r```: commitment
- ```c```: challenge
- ```s```: response

Used as a transport object between the prover and verifier.
Its ```toString()``` method outputs hex-encoded values for readability.

### ```Main.java```

Demonstrates a full execution of the protocol:

1. Generates secure parameters ($p$, $q$, $g$).
2. Creates a ```KeyPair``` for the ```Prover```.
3. Initializes ```Prover``` and ```Verifier```.
4. Executes one full identification round:
   - Prover sends commitment ```r```
   - Verifier sends challenge ```c```
   - Prover returns ```Proof(r, c, s)```
   - Verifier checks and prints the result

## Testing

The project includes a concise JUnit 5 test suite covering the main theoretical properties of the Schnorr protocol:
completeness, soundness, and zero-knowledge, plus one robustness check against invalid proofs.

### ```testProtocolVerification()```
Verifies completeness: honest prover and verifier always succeed.
Ensures the core verification equation  $g^𝑠 ≡ 𝑟 \cdot 𝑦^𝑐 mod(𝑝)$ holds for valid proofs.

### ```testSoundnessViaRewinding()```
Demonstrates soundness via the rewinding argument.
Two valid transcripts with the same commitment $r$ but different challenges allow extracting the prover’s secret $x$, confirming the *proof-of-knowledge* property.

### ```testZeroKnowledge()```
Confirms zero-knowledge: simulated transcripts created without knowing the secret still verify successfully, showing that the verifier learns nothing about $x$.

### ```testInvalidProof()```
Checks robustness: invialid proofs are correctly rejected by the verifier.

## Running the Demo
```
./gradlew run
```

or, from Eclipse:

Run → Main.java

Example output:
```
=== Schnorr Zero-Knowledge Proof Demo ===

[Parameters]
Parameters {
  p = 508150370065779801213387943141503126563,
  q = 254075185032889900606693971570751563281,
  g = 424030122054390383955382977622240861779
}

[Key Pair]
KeyPair {
  (private key hidden),
  y (public) = 200947051474585436195635815030571466181
}

[Prover → Verifier] Commitment r = 17883297947470169822363002634013789875

[Verifier → Prover] Challenge c = 210218893716285914523563881504252794249

[Prover → Verifier] Proof = Proof {r=d7432a9b700ad77bd49375a6da44eb3, c=9e26afacaa5934018ae9b763c1f29589, s=51b3bf35cb8a64dcd715e6e670677f68}

[Verifier] Verification result: ACCEPTED
```

## Security Notes
**Cryptographically secure randomness**:
All nonces and private values ($x$, $k$, $c$) are generated using Java’s ```SecureRandom```, which provides cryptographically strong random numbers.
This prevents reuse of $k$, a common implementation flaw that can reveal the secret key through linear equations.

**Parameter generation correctness**:
The generator $g$ is constructed as $g = h^{(p−1)/q} mod (p)$ to ensure that $g$ has exact order $q$ in the multiplicative group $ℤ*_p$.
This guarantees that all proofs operate in the correct subgroup and prevents attacks based on small subgroup confinement.

**Private key handling**:
The secret key $x$ is stored internally as a ```byte[]``` and only converted to ```BigInteger``` temporarily for modular arithmetic.
While Java’s memory model does not guarantee true key erasure, this design enables theoretical zeroization by overwriting temporary buffers.
The private key is never printed, logged, or exposed through public accessors.

**Isolation of secret operations**:
All operations involving the private key are confined to the ```KeyPair``` class via the ```multiplySecret()``` and ```matchesSecret()``` methods, which prevent unintentional key leakage to other layers (such as ```Prover``` or ```Verifier```).

**Educational scope disclaimer**:
This implementation is intended for academic and demonstrative use.

## License

This project is released under the MIT License. For full terms, see the [LICENSE](./LICENSE) file.
