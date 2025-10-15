package model;

import java.math.BigInteger;

public class Proof {
    private final BigInteger r;  // Commitment
    private final BigInteger c;  // Challenge
    private final BigInteger s;  // Response
    

    public Proof(BigInteger r, BigInteger c, BigInteger s) {
        this.r = r;
        this.c = c;
        this.s = s;
    }

    public BigInteger getR() { return r; }
    public BigInteger getC() { return c; }
    public BigInteger getS() { return s; }

    @Override
    public String toString() {
        return "Proof {" +
                "r=" + r.toString(16) +
                ", c=" + c.toString(16) +
                ", s=" + s.toString(16) +
                '}';
    }
}

