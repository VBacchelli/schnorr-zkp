package schnorrzkp;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;

import model.KeyPair;
import model.Parameters;
import model.Proof;
import util.CryptoUtils;
import core.Prover;
import core.Verifier;
import core.Simulator;

public class SchnorrTest {

    @Test
    void testProtocolVerification() {
        Parameters params = Parameters.demo();
        KeyPair kp = new KeyPair(params);
        Prover prover = new Prover(params, kp);
        Verifier verifier = new Verifier(params);

        BigInteger r = prover.generateCommitment();
        BigInteger c = verifier.generateChallenge();
        Proof proof = prover.respondToChallenge(c);

        assertTrue(verifier.verify(proof, kp.getPublic()), "Valid proof should verify successfully");
    }

    @Test
    void testSoundnessViaRewinding() {
        Parameters params = Parameters.demo();
        KeyPair kp = new KeyPair(params); // generates x (private), y (public)

        // Step 1: Prover creates a single commitment
        Prover prover = new Prover(params, kp);
        BigInteger t = prover.generateCommitment(); // g^k mod p

        // Step 2: Verifier issues two different challenges
        BigInteger c1 = CryptoUtils.randomZq(params.getQ());
        BigInteger c2 = CryptoUtils.randomZq(params.getQ());
        assertNotEquals(c1, c2, "Challenges must differ for extraction");

        // Step 3: Prover computes two responses for the same commitment
        Proof p1 = prover.respondToChallenge(c1);
        Proof p2 = prover.respondToChallenge(c2);

        // Step 4: Verify both proofs are valid
        Verifier verifier = new Verifier(params);
        boolean valid1 = verifier.verify(p1, kp.getPublic());
        boolean valid2 = verifier.verify(p2, kp.getPublic());

        assertTrue(valid1 && valid2, "Both transcripts must be valid for soundness extraction");

        // Step 5: Extract the secret using rewinding formula
        BigInteger q = params.getQ();
        BigInteger sDiff = p1.getS().subtract(p2.getS()).mod(q);
        BigInteger cDiff = c1.subtract(c2).mod(q);
        BigInteger cDiffInv = cDiff.modInverse(q);
        BigInteger extractedX = sDiff.multiply(cDiffInv).mod(q);

        // Step 6: Assert the extracted secret matches the true private key
        assertTrue(kp.matchesSecret(extractedX), 
            "Extractor should recover the prover's private key");
    }
    
    @Test
    void testZeroKnowledge() {
        Parameters params = Parameters.demo();
        KeyPair kp = new KeyPair(params);
        Verifier verifier = new Verifier(params);
        Simulator simulator = new Simulator(params, kp.getPublic());

        Proof fakeProof = simulator.simulateProof();
        assertTrue(verifier.verify(fakeProof, kp.getPublic()), "Simulated proof should verify (indistinguishable)");
    }
    
    @Test
    void testInvalidProof() {
        Parameters params = Parameters.demo();
        KeyPair kp = new KeyPair(params);
        Verifier v = new Verifier(params);

        BigInteger c = v.generateChallenge();
        BigInteger q = params.getQ(), p = params.getP(), g = params.getG(), y = kp.getPublic();

        BigInteger s = CryptoUtils.randomZq(q);
        BigInteger rBad = g.modPow(s, p).multiply(y.modPow(c, p)).add(BigInteger.ONE).mod(p);

        assertFalse(v.verify(new Proof(rBad, c, s), kp.getPublic()));
    }
}
