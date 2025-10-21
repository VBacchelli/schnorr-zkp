# Schnorr Identification Protocol (Zero Knowledge Proof)

🇮🇹 - [Leggi in Italiano](./README_it.md)

## Introduction
This project is an implementation of the Schnorr identification protocol, a classic example of a Zero-Knowledge Proof of Knowledge (ZKPoK).

It demonstrates how a prover can convince a verifier of knowing a secret x such that y = g^x mod p, without revealing x itself.

This project was developed as part of the Information Security M (Sicurezza dell'Informazione M) course of University Of Bologna to demonstrate the implementation of a Zero-Knowledge Proof protocol in Java.

## Project Structure
| Package | Description                                             |
| ------- | ------------------------------------------------------- |
| `model` | Data structures (`Parameters`, `KeyPair`, `Proof`)      |
| `core`  | Core protocol logic (`Prover`, `Verifier`, `Simulator`) |
| `util`  | Cryptographic utilities (randomness, helpers)           |
| `app`   | Demo entry point (`Main.java`)                          |
| `test`  | JUnit test suite (soundness, forgery tests)             |

## Protocol steps
**Setup**: public parameters (p, q, g) define a subgroup of $ℤ^*_p$ of order q.

**Key Generation**:

- Private key: $x ∈ Z_q$
- Public key: $y = g^x mod (p)$

**Identification Round**:

- Prover picks random k, sends $r = g^k mod (p)$.
- Verifier sends random challenge c.
- Prover responds with $s = (k + c\cdot x) mod (q)$.
- Verifier checks $g^s ≡ r\cdot y^c mod (p)$.

## Security Notes
**Cryptographically secure randomness**:
All nonces and private values (x, k, c) are generated using Java’s SecureRandom, which provides cryptographically strong random numbers.
This prevents reuse of k, a common implementation flaw that can reveal the secret key through linear equations.

**Parameter generation correctness**:
The generator g is constructed as $g = h^{(p−1)/q} mod (p)$ to ensure that g has exact order q in the multiplicative group $ℤ*_p$.
This guarantees that all proofs operate in the correct subgroup and prevents attacks based on small subgroup confinement.

**Private key handling**:
The secret key x is stored internally as a byte[] and only converted to BigInteger temporarily for modular arithmetic.
While Java’s memory model does not guarantee true key erasure, this design enables theoretical zeroization by overwriting temporary buffers.
The private key is never printed, logged, or exposed through public accessors.

**Isolation of secret operations**:
All operations involving the private key are confined to the KeyPair class via the multiplySecret() and matchesSecret() methods, which prevent unintentional key leakage to other layers (such as Prover or Verifier).

**Educational scope disclaimer**:
This implementation is intended for academic and demonstrative use.
