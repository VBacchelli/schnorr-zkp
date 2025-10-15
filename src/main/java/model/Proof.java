package model;

import java.math.BigInteger;

public class Proof {
    private final BigInteger t;  // Commitment
    private final BigInteger c;  // Challenge
    private final BigInteger s;  // Response
    

    public Proof(BigInteger t, BigInteger c, BigInteger s) {
        this.t = t;
        this.c = c;
        this.s = s;
    }

    public BigInteger getT() { return t; }
    public BigInteger getC() { return c; }
    public BigInteger getS() { return s; }

    @Override
    public String toString() {
        return "Proof {" +
                "t=" + t.toString(16) +
                ", c=" + c.toString(16) +
                ", s=" + s.toString(16) +
                '}';
    }
}

