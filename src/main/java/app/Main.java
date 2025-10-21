package app;

import model.*;

import java.math.BigInteger;

import core.*;

/**
 * Demonstrates a complete execution of the Schnorr identification protocol.
 *
 * <p>This example generates parameters, creates a Prover and a Verifier,
 * and performs a single identification round to show how the proof succeeds.
 */
public class Main {

    public static void main(String[] args) {
        System.out.println("=== Schnorr Zero-Knowledge Proof Demo ===\n");

        // Step 1: Generate Schnorr parameters (safe for demo, not for production)
        Parameters params = Parameters.generate(128); // 128-bit q for speed
        System.out.println("[Parameters]");
        System.out.println(params + "\n");

        // Step 2: Generate Prover’s key pair
        KeyPair kp = new KeyPair(params);
        System.out.println("[Key Pair]");
        System.out.println(kp + "\n");

        // Step 3: Create Prover and Verifier
        Prover prover = new Prover(params, kp);
        Verifier verifier = new Verifier(params);

        // Step 4: Prover generates commitment
        BigInteger commitment = prover.generateCommitment();
        System.out.println("[Prover → Verifier] Commitment r = " + commitment + "\n");

        // Step 5: Verifier issues challenge
        BigInteger challenge = verifier.generateChallenge();
        System.out.println("[Verifier → Prover] Challenge c = " + challenge + "\n");

        // Step 6: Prover computes response and sends proof
        Proof proof = prover.respondToChallenge(challenge);
        System.out.println("[Prover → Verifier] Proof = " + proof + "\n");

        // Step 7: Verifier checks proof
        boolean valid = verifier.verify(proof, kp.getPublic());
        System.out.println("[Verifier] Verification result: " + (valid ? "ACCEPTED" : "REJECTED"));

        System.out.println("\n=== End of Demo ===");
    }
}
