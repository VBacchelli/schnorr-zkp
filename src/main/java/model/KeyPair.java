package model;

import java.math.BigInteger;
import java.util.Arrays;
import util.CryptoUtils;

/**
 * Represents a Schnorr key pair (x, y),
 * where x is the private key and y = g^x mod p is the public key.
 *
 * <p>This class is designed for secure handling:
 * <ul>
 *   <li>The private key is stored only as a byte array, never as a BigInteger.</li>
 *   <li>All conversions to BigInteger are temporary and wiped immediately.</li>
 *   <li>The key can be zeroized with {@link #destroy()} when no longer needed.</li>
 * </ul>
 *
 * <p>Note: In production, private keys should be encrypted when persisted.</p>
 */
public final class KeyPair {

    /** Secret exponent x, stored securely as bytes. */
    private final byte[] privateKeyBytes;

    /** Public key y = g^x mod p (safe to share). */
    private final BigInteger publicKey;

    /** Associated Schnorr parameters (p, q, g). */
    private final Parameters params;

    /**
     * Generates a new random Schnorr key pair securely.
     *
     * @param params the Schnorr public parameters (p, q, g)
     */
    public KeyPair(Parameters params) {
        this.params = params;

        BigInteger q = params.getQ();
        BigInteger x = CryptoUtils.randomZq(q);
        this.privateKeyBytes = x.toByteArray();

        // Compute y = g^x mod p
        this.publicKey = params.getG().modPow(x, params.getP());
    }

    /**
     * (Testing only) Creates a key pair from an existing private key.
     * 
     * @param params the Schnorr parameters
     * @param privateKey the secret exponent (0 < x < q)
     */
    public KeyPair(Parameters params, BigInteger privateKey) {
        this.params = params;

        if (privateKey.signum() <= 0 || privateKey.compareTo(params.getQ()) >= 0) {
            throw new IllegalArgumentException("Private key must be in range (0, q)");
        }

        this.privateKeyBytes = privateKey.toByteArray();
        this.publicKey = params.getG().modPow(privateKey, params.getP());
    }

    /** Returns the public key y = g^x mod p (safe to share). */
    public BigInteger getPublic() {
        return publicKey;
    }

    /** Returns the parameters (p, q, g) used by this key pair. */
    public Parameters getParameters() {
        return params;
    }

    /** 
     * Compares a candidate value with the true private key (without exposing it).
     * Used for testing soundness.
     */
    public boolean matchesSecret(BigInteger candidate) {
    	BigInteger x = new BigInteger(1, privateKeyBytes);
        return x.mod(params.getQ()).equals(candidate.mod(params.getQ()));
    }

    /**
     * Computes (privateKey * value) mod q without exposing the private key.
     * Used by the Prover when computing the Schnorr response. Should not be called elsewhere.
     * The method uses mod(q) to mask the linear relation with the secret, 
     * making it safe to keep the method public for use in the Prover class.
     */
    public BigInteger multiplySecret(BigInteger value) {
    	BigInteger x = new BigInteger(1, privateKeyBytes);
        return value.multiply(x).mod(params.getQ());
    }

    /**
     * Best-effort zeroization of the stored private key bytes.
     * Call this when the key is no longer needed.
     */
    public void destroy() {
        Arrays.fill(privateKeyBytes, (byte) 0);
    }

    @Override
    public String toString() {
        return "KeyPair {" +
                "\n  (private key hidden)" +
                ",\n  y (public) = " + publicKey +
                "\n}";
    }
}
