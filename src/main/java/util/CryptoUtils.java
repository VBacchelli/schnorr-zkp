package util;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class CryptoUtils {
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

    private CryptoUtils() {}

    public static BigInteger randomZq(BigInteger q) {
        BigInteger r;
        do {
            r = new BigInteger(q.bitLength(), RANDOM);
        } while (r.signum() <= 0 || r.compareTo(q) >= 0);
        return r;
    }
}
