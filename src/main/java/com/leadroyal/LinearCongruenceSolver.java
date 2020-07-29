package com.leadroyal;

import java.math.BigInteger;

public class LinearCongruenceSolver {
    // ax + by = 1
    public static long[] exgcd(long a, long b) {
        long[] result = new long[3];
        if (b == 0) {
            result[0] = a;
            result[1] = 1;
            result[2] = 0;
            return result;
        }
        long[] temp = exgcd(b, a % b);
        long ans = temp[0];
        result[0] = ans;
        result[1] = temp[2];
        result[2] = temp[1] - (a / b) * temp[2];
        System.out.println(String.format("gcd,x,y: %d %d %d", result[0], result[1], result[2]));
        return result;
    }

    // ax = b mod n
    public static long solve_linear_congruence(long a, long b, long n) {
        long[] r = exgcd(a, n);
        long gcd = r[0];
        long x = r[1];
        long y = r[2];
        assert gcd == 1;
        long x0 = x * b / gcd % n;
        if (x0 < 0)
            x0 += n;
        return x0;
    }

    public static BigInteger[] exgcd(BigInteger a, BigInteger b) {
        BigInteger[] result = new BigInteger[3];
        if (b.equals(BigInteger.ZERO)) {
            result[0] = a;
            result[1] = BigInteger.ONE;
            result[2] = BigInteger.ZERO;
        } else {
            BigInteger[] temp = exgcd(b, a.mod(b));
            result[0] = temp[0];
            result[1] = temp[2];
            result[2] = temp[1].subtract((a.divide(b)).multiply(temp[2]));
            System.out.println(String.format("gcd,x,y: %d %d %d", result[0], result[1], result[2]));
        }
        return result;
    }

    public static BigInteger solve(BigInteger a, BigInteger b, BigInteger n) {
        BigInteger[] r = exgcd(a, n);
        BigInteger gcd = r[0];
        BigInteger x = r[1];
        BigInteger y = r[2];
        assert gcd.equals(BigInteger.ONE);
        return x.multiply(b).divide(gcd).mod(n);
    }

}
