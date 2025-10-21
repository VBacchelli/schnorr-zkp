package model;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Represents the public parameters (p, q, g) of the Schnorr identification scheme.
 *
 * <p>These parameters define a cyclic subgroup of order q within the multiplicative
 * group ℤₚ*. The class guarantees that all public instances are valid:
 * parameters are either securely generated or taken from a trusted demo set.
 *
 * <p>Instances are immutable and thread-safe.
 */
public final class Parameters {

    /** Bit-length of probabilistic prime testing (accuracy ≈ 1 - 2^-50). */
    private static final int PRIME_CERTAINTY = 50;

    /** Secure random source (thread-safe in modern JVMs). */
    private static final SecureRandom RANDOM;
    static { // static block, only runs once and initializes RANDOM
        SecureRandom rnd;
        try {
            rnd = SecureRandom.getInstanceStrong(); // takes the best available instance
        } catch (Exception e) {
            rnd = new SecureRandom(); //fallback, default instance (system dependent)
        }
        RANDOM = rnd;
    }

    private final BigInteger p; // Large prime modulus
    private final BigInteger q; // Subgroup order
    private final BigInteger g; // Generator of the subgroup

    /**
     * Internal constructor used only by trusted factory methods.
     * <p>Use {@link #generate(int)} to obtain secure random parameters
     * or {@link #demo()} for small, non-secure educational examples.
     */
    private Parameters(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    /**
     * Convenience constructor that automatically generates parameters.
     * <p>Equivalent to calling {@code Parameters.generate(bits)}.
     *
     * @param bits bit length for q (e.g., 256 or 512)
     */
    public Parameters(int bits) {
        Parameters generated = generate(bits);
        this.p = generated.p;
        this.q = generated.q;
        this.g = generated.g;
    }

    /**
     * Generates a new set of valid parameters (p, q, g) for Schnorr’s protocol.
     *
     * <p>The function ensures:
     * <ul>
     *   <li>q is prime,</li>
     *   <li>p = kq + 1 is also prime,</li>
     *   <li>g has order q modulo p.</li>
     * </ul>
     *
     * @param bits bit length for q
     * @return a new immutable {@code Parameters} instance
     */
    public static Parameters generate(int bits) {
        BigInteger q = BigInteger.probablePrime(bits, RANDOM);

        // Find a safe prime p = k*q + 1
        BigInteger k = BigInteger.TWO;
        BigInteger p = k.multiply(q).add(BigInteger.ONE);
        while (!p.isProbablePrime(PRIME_CERTAINTY)) {
            k = k.add(BigInteger.ONE);
            p = k.multiply(q).add(BigInteger.ONE);
        }

        // Find generator g of order q mod p
        BigInteger g = findGenerator(p, q);

        return new Parameters(p, q, g);
    }

    /**
     * Finds a generator g of order q modulo p.
     *
     * @param p prime modulus
     * @param q subgroup order
     * @return a generator g satisfying g^q ≡ 1 (mod p)
     * @throws IllegalStateException if no valid generator is found
     */
    private static BigInteger findGenerator(BigInteger p, BigInteger q) {
    	BigInteger exp = p.subtract(BigInteger.ONE).divide(q); // (p-1)/q
        while (true) {
            // choose h ∈ {2, …, p-2}
            BigInteger h;
            do {
                h = new BigInteger(p.bitLength() - 1, RANDOM);
            } while (h.compareTo(BigInteger.TWO) < 0 || h.compareTo(p.subtract(BigInteger.TWO)) > 0);

            BigInteger g = h.modPow(exp, p);   // g = h^{(p-1)/q} mod p
            if (!g.equals(BigInteger.ONE)) {
                return g; // ord(g) = q
            }
        }
    }

    /**
     * Returns a small, human-readable demo parameter set.
     * <p><b>Warning:</b> not secure for cryptographic use. Provided for
     * educational and debugging purposes only.
     *
     * @return a {@code Parameters} instance with small fixed values
     */
    public static Parameters demo() {
        BigInteger q = BigInteger.valueOf(11);
        BigInteger p = q.multiply(BigInteger.TWO).add(BigInteger.ONE); // p = 23
        BigInteger g = BigInteger.valueOf(2);
        return new Parameters(p, q, g);
    }


    // --- Accessors ---

    /** @return the prime modulus p */
    public BigInteger getP() { return p; }

    /** @return the subgroup order q */
    public BigInteger getQ() { return q; }

    /** @return the generator g of the subgroup */
    public BigInteger getG() { return g; }

    @Override
    public String toString() {
        return String.format(
            "Parameters {%n  p = %s,%n  q = %s,%n  g = %s%n}",
            p, q, g
        );
    }
}
