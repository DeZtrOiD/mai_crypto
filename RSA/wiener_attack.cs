using System.Numerics;
using System.Collections.Generic;

namespace RSA;

public record WienerAttackResult(BigInteger D, BigInteger Phi, List<(BigInteger Numerator, BigInteger Denominator)> Convergents);

public static class WienerAttack {
    public static WienerAttackResult? MakeWienerAttack(BigInteger n, BigInteger e) {
        if (n <= 0 || e <= 0)
            throw new ArgumentException("n and e must be positive.");

        var (numerator, denominator) = (e, n);
        var convergentH = (BigInteger.Zero, BigInteger.One);
        var convergentK = (BigInteger.One, BigInteger.Zero);

        var convergents = new List<(BigInteger, BigInteger)>();

        while (denominator != 0) {
            BigInteger quotient = numerator / denominator;
            (numerator, denominator) = (denominator, numerator % denominator);

            BigInteger newH = quotient * convergentH.Item2 + convergentH.Item1;
            BigInteger newK = quotient * convergentK.Item2 + convergentK.Item1;

            (convergentH.Item1, convergentH.Item2) = (convergentH.Item2, newH);
            (convergentK.Item1, convergentK.Item2) = (convergentK.Item2, newK);
            // add p, q
            convergents.Add((convergentH.Item2, convergentK.Item2));

            if (convergentK.Item2 > 1 && convergentH.Item2 > 1) {
                BigInteger phiNumerator = e * convergentK.Item2 - 1;
                if (phiNumerator % convergentH.Item2 == 0) {
                    BigInteger phi = phiNumerator / convergentH.Item2;

                    BigInteger sumPQ = n - phi + 1;
                    BigInteger discriminant = sumPQ * sumPQ - 4 * n;

                    if (discriminant >= 0) {
                        BigInteger sqrtDisc = IntegerSquareRoot(discriminant);
                        if (sqrtDisc * sqrtDisc == discriminant) {
                            BigInteger p = (sumPQ + sqrtDisc) / 2;
                            if (p > 1 && n % p == 0) {
                                return new WienerAttackResult(convergentK.Item2, phi, convergents);
                            }
                        }
                    }
                }
            }
        }

        return null;
    }

    private static BigInteger IntegerSquareRoot(BigInteger value) {
        if (value < 2) return value;

        BigInteger x = value;
        BigInteger y = (x + 1) / 2;

        while (y < x) {
            x = y;
            y = (x + value / x) / 2;
        }

        return x;
    }
}
