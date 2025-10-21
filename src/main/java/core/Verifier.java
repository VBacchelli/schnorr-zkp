package core;

import java.math.BigInteger;
import model.Parameters;
import model.Proof;
import util.CryptoUtils;

/**
 * Verifier for the Schnorr identification protocol.
 *
 * <p>The verifier:
 * 1. Generates a random challenge c in Z_q.
 * 2. Verifies the prover's response (r, c, s) by checking:
 *      g^s ≡ r * y^c (mod p)
 */
public class Verifier {

    private final Parameters params;

    public Verifier(Parameters params) {
        this.params = params;
    }

    /**
     * Step 2 (interactive): Generate a random challenge c in Z_q.
     */
    public BigInteger generateChallenge() {
        return CryptoUtils.randomZq(params.getQ());
    }

    /**
     * Step 3: Verify the Schnorr proof (r, c, s).
     *
     * @param proof the proof object containing r, c, s
     * @return true if the proof is valid, false otherwise
     */
    public boolean verify(Proof proof, BigInteger publicKey) {
        BigInteger p = params.getP();
        BigInteger g = params.getG();

        BigInteger left = g.modPow(proof.getS(), p); // g^s mod p
        BigInteger right = proof.getR()
                .multiply(publicKey.modPow(proof.getC(), p))
                .mod(p); // r * y^c mod p
        
        //System.out.println("[DEBUG] g^s mod p = " + left);
        //System.out.println("[DEBUG] r * y^c mod p = " + right);


        return left.equals(right);
    }
}
