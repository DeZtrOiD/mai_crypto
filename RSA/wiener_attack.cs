using System.Numerics;
using System.Collections.Generic;

namespace RSA;

public record WienerAttackResult(BigInteger D, BigInteger Phi, List<(BigInteger Numerator, BigInteger Denominator)> Convergents);

public static class WienerAttack {
    public static WienerAttackResult? MakeWienerAttack(BigInteger n, BigInteger e) {
        if (n <= 0 || e <= 0)
            throw new ArgumentException("n and e must be positive.");

        var (numerator, denominator) = (e, n);
        // convergent
        var conP = (BigInteger.Zero, BigInteger.One); // p 0 1
        var conQ = (BigInteger.One, BigInteger.Zero); // q 1 0

        var convergents = new List<(BigInteger, BigInteger)>();

        while (denominator != 0) {
            BigInteger quotient = numerator / denominator;
            (numerator, denominator) = (denominator, numerator % denominator);

            BigInteger newP = quotient * conP.Item2 + conP.Item1;
            BigInteger newQ = quotient * conQ.Item2 + conQ.Item1;

            (conP.Item1, conP.Item2) = (conP.Item2, newP);
            (conQ.Item1, conQ.Item2) = (conQ.Item2, newQ);
            // add p, q
            convergents.Add((conP.Item2, conQ.Item2));

            if (conQ.Item2 > 1 && conP.Item2 > 1) {
                BigInteger phiNumerator = e * conQ.Item2 - 1;
                if (phiNumerator % conP.Item2 == 0) {
                    BigInteger phi = phiNumerator / conP.Item2;

                    BigInteger sumPQ = n - phi + 1;
                    BigInteger discriminant = sumPQ * sumPQ - 4 * n;

                    if (discriminant >= 0) {
                        BigInteger sqrtDisc = IntegerSquareRoot(discriminant);
                        if (sqrtDisc * sqrtDisc == discriminant) {
                            BigInteger p = (sumPQ + sqrtDisc) / 2;
                            if (p > 1 && n % p == 0) {
                                return new WienerAttackResult(conQ.Item2, phi, convergents);
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
