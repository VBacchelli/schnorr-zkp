package model;

import java.math.BigInteger;
import java.util.Arrays;
import util.CryptoUtils;

/**
 * Represents a Schnorr key pair (x, y),
 * where x is the private key and y = g^x mod p is the public key.
 *
 * <p>This class is immutable and designed for secure handling:
 * - the private key is never printed or exposed directly
 * - optional memory zeroization is supported via destroy()
 * 
 * <p>Note: In a production environment, private keys should also be encrypted
 * if stored persistently (not deemed necessary in this academic demo).
 */
public final class KeyPair {

    private final BigInteger privateKey; // secret (x)
    private final BigInteger publicKey;  // public (y)
    private final Parameters params;

    /**
     * Generates a new random Schnorr key pair securely.
     *
     * @param params the Schnorr public parameters (p, q, g)
     */
    public KeyPair(Parameters params) {
        this.params = params;
        this.privateKey = CryptoUtils.randomZq(params.getQ());      // x ← random in Z_q
        this.publicKey = params.getG().modPow(privateKey, params.getP()); // y = g^x mod p
    }

    /**
     * (Testing only)
     * Creates a key pair from an existing private key.
     *
     * @param params the Schnorr public parameters
     * @param privateKey a known secret value (must be in (0, q))
     */
    public KeyPair(Parameters params, BigInteger privateKey) {
        this.params = params;
        if (privateKey.signum() <= 0 || privateKey.compareTo(params.getQ()) >= 0) {
            throw new IllegalArgumentException("Private key must be in range (0, q)");
        }
        this.privateKey = privateKey;
        this.publicKey = params.getG().modPow(privateKey, params.getP());
    }

    /**
     * Returns the public key y = g^x mod p (safe to share).
     */
    public BigInteger getPublic() {
        return publicKey;
    }

    /**
     * Returns the parameters (p, q, g) used to generate this key pair.
     */
    public Parameters getParameters() {
        return params;
    }

    /**
     * Provides a defensive copy of the private key.
     * The returned value should not be stored or logged.
     *
     * @return a copy of the private key
     */
    public BigInteger copyPrivateKey() {
        return new BigInteger(privateKey.toByteArray());
    }

    /**
     * Best-effort memory zeroization of the private key bytes.
     * Note: JVM immutability of BigInteger prevents guaranteed erasure.
     */
    public void destroy() {
        byte[] bytes = privateKey.toByteArray();
        Arrays.fill(bytes, (byte) 0);
    }

    @Override
    public String toString() {
        return "KeyPair {" +
                "\n  (private key hidden)" +
                ",\n  y (public) = " + publicKey +
                "\n}";
    }
}
