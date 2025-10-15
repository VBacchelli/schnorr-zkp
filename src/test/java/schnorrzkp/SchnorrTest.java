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
        KeyPair keyPair = new KeyPair(params);
        Prover prover = new Prover(params, keyPair);
        Verifier verifier = new Verifier(params, keyPair.getPublic());

        BigInteger r = prover.generateCommitment();
        BigInteger c = verifier.generateChallenge();
        Proof proof = prover.respondToChallenge(c);

        assertTrue(verifier.verify(proof), "Valid proof should verify successfully");
    }

    @Test
    void testSimulatorProducesValidLookingProof() {
        Parameters params = Parameters.demo();
        KeyPair keyPair = new KeyPair(params);
        Verifier verifier = new Verifier(params, keyPair.getPublic());
        Simulator simulator = new Simulator(params, keyPair.getPublic());

        Proof fakeProof = simulator.simulateProof();
        assertTrue(verifier.verify(fakeProof), "Simulated proof should verify (indistinguishable)");
    }
    
    @Test
    void testInvalidProof() {
        Parameters params = Parameters.demo();
        KeyPair kp = new KeyPair(params);
        Verifier v = new Verifier(params, kp.getPublic());

        BigInteger c = v.generateChallenge();
        BigInteger q = params.getQ(), p = params.getP(), g = params.getG(), y = kp.getPublic();

        BigInteger s = CryptoUtils.randomZq(q);
        BigInteger rBad = g.modPow(s, p).multiply(y.modPow(c, p)).add(BigInteger.ONE).mod(p);

        assertFalse(v.verify(new Proof(rBad, c, s)));
    }
}
