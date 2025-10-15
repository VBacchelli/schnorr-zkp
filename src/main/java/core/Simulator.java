package core;

import java.math.BigInteger;
import model.Parameters;
import model.Proof;
import util.CryptoUtils;

/**
 * Simulator for Schnorr’s zero-knowledge property.
 * Generates valid-looking (r, c, s) triples without knowing the secret key.
 */
public class Simulator {

    private final Parameters params;
    private final BigInteger publicKey;

    public Simulator(Parameters params, BigInteger publicKey) {
        this.params = params;
        this.publicKey = publicKey;
    }

    /**
     * Generates a simulated proof indistinguishable from a real one:
     *   choose random c, s ∈ Z_q
     *   compute r = g^s * y^{-c} mod p
     */
    public Proof simulateProof() {
        BigInteger q = params.getQ();
        BigInteger p = params.getP();
        BigInteger g = params.getG();

        BigInteger c = CryptoUtils.randomZq(q);
        BigInteger s = CryptoUtils.randomZq(q);

        // r = g^s * y^{-c} mod p
        BigInteger yInvC = publicKey.modPow(c.negate().mod(q), p);
        BigInteger r = g.modPow(s, p).multiply(yInvC).mod(p);

        return new Proof(r, c, s);
    }
}
