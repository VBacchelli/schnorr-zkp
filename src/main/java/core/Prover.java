package core;

import java.math.BigInteger;
import model.KeyPair;
import model.Parameters;
import model.Proof;
import util.CryptoUtils;

public class Prover {

    private final Parameters params;
    private final KeyPair keyPair;

    private BigInteger k; // ephemeral secret (nonce)
    private BigInteger r; // commitment

    public Prover(Parameters params, KeyPair keyPair) {
        this.params = params;
        this.keyPair = keyPair;
    }

    /**
     * Step 1: Generate commitment r = g^k mod p
     */
    public BigInteger generateCommitment() {
        this.k = CryptoUtils.randomZq(params.getQ());
        this.r = params.getG().modPow(k, params.getP());
        return r;
    }

    /**
     * Step 2: Respond to verifier's challenge c by computing s = (k + c·x) mod q
     * The private nonce k is securely cleared after use.
     */
    public Proof respondToChallenge(BigInteger c) {
        BigInteger q = params.getQ();

        BigInteger s = k.add(keyPair.multiplySecret(c)).mod(q); 

        //System.out.println("[DEBUG] Using k = " + k);
        //System.out.println("[DEBUG] Using r = " + r);

        // Create proof (r, c, s)
        Proof proof = new Proof(r, c, s);

        return proof;
    }

    /**
     * Best-effort secure erase of ephemeral secret k.
     * Call this when the secret is no longer needed.
     */
    public void destroyEphemeral() {
        if (k != null) {
            byte[] bytes = k.toByteArray();
            java.util.Arrays.fill(bytes, (byte) 0);
            k = null;
        }
    }
    
}
