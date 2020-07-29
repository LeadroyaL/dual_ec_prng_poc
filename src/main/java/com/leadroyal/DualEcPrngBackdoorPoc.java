package com.leadroyal;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Random;

public class DualEcPrngBackdoorPoc {
    public static void main(String[] args) throws Exception {
        ECCurve curve = NISTNamedCurves.getByName("P-256").getCurve();
        // g 是NSA约定好的基点
        BigInteger gx = new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
        BigInteger gy = new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
        ECPoint gPoint = curve.createPoint(gx, gy);
        // n 是NSA约定好的秩
        BigInteger n = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);

        // 随机选取一个 p,q，获得 pPoint 和 qPoint，毕竟 NSA 的 pPoint 和 qPoint 也是这么来的
        BigInteger p = new BigInteger("112233445566778899", 16);
        BigInteger q = new BigInteger("998877665544332211", 16);
        ECPoint pPoint = gPoint.multiply(p).normalize();
        ECPoint qPoint = gPoint.multiply(q).normalize();
        // 求解线性同余方程 q * e = p mod n，得到 e
        BigInteger e = LinearCongruenceSolver.solve(q, p, n);
        System.out.println("e " + e.toString(16));
        // ri 来自上一个点的横坐标，可以视为随机数，
        byte[] tmp = new byte[32];
        new Random().nextBytes(tmp);
        BigInteger ri = new BigInteger(1, tmp).mod(n);
        System.out.println("ri " + ri.toString(16));
        // 算法输出的当前随机数是 qPoint*ri 的横坐标的低 240bit
        ECPoint q_mul_ri = qPoint.multiply(ri).normalize();
        byte[] currentRandom256 = q_mul_ri.getXCoord().getEncoded();
        byte[] currentRandom240 = new byte[30];
        System.arraycopy(currentRandom256, 2, currentRandom240, 0, 30);
        System.out.println("currentRandom(ti) " + bytesToHex(currentRandom256));
        System.out.println("currentRandom240(ti) " + bytesToHex(currentRandom240));
        // pPoint*ri 得到下一个点
        ECPoint nextPoint = pPoint.multiply(ri).normalize();
        System.out.println("nextPoint " + nextPoint);

        // 下文是攻击者视角，输入仅有 currentRandom 和 e
        byte[] compressedBytes = new byte[33];
        System.arraycopy(currentRandom240, 0, compressedBytes, 3, 30);
        ECPoint calc_q_mul_ri, predict1, predict2;

        // 需要爆破 2 个被移除的 byte
        boolean hit = false;
        for (int i = 0; i < 256; i++) {
            if (hit)
                break;
            System.out.println(String.format("process %d/256", i));
            for (int j = 0; j < 256; j++) {
                compressedBytes[1] = (byte) i;
                compressedBytes[2] = (byte) j;
                try {
                    compressedBytes[0] = 2;
                    // 恢复出 qPoint*ri
                    calc_q_mul_ri = curve.decodePoint(compressedBytes);
                    // qPoint*ri*e = pPoint*ri，预测下一个点
                    predict1 = calc_q_mul_ri.multiply(e).normalize();
                    // 椭圆曲线存在双解的情况，这里两个解都要试一次
                    predict2 = predict1.negate();
                    if (predict1.equals(nextPoint) || predict2.equals(nextPoint)) {
                        System.out.println("hit!");
                        hit = true;
                        System.out.println("predict nextPoint 1:" + predict1);
                        System.out.println("predict nextPoint 2:" + predict2);
                        break;
                    }
                } catch (Exception ignore) {
                    // 并不是所有的 x 都有解，需要 catch 一下
                }
            }
        }

        if (hit) {
            System.out.println("predict success!");
        } else {
            System.out.println("predict fail!");
        }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}