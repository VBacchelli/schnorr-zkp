package util;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class CryptoUtils {
    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoUtils() {}

    public static BigInteger randomZq(BigInteger q) {
        BigInteger r;
        do {
            r = new BigInteger(q.bitLength(), RANDOM);
        } while (r.signum() <= 0 || r.compareTo(q) >= 0);
        return r;
    }
}
