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
        var conK = (BigInteger.Zero, BigInteger.One); // p 0 1
        var conD = (BigInteger.One, BigInteger.Zero); // q 1 0

        var convergents = new List<(BigInteger, BigInteger)>();

        while (denominator != 0) {
            BigInteger quotient = numerator / denominator;
            (numerator, denominator) = (denominator, numerator % denominator);

            BigInteger newK = quotient * conK.Item2 + conK.Item1;
            BigInteger newD = quotient * conD.Item2 + conD.Item1;

            (conK.Item1, conK.Item2) = (conK.Item2, newK);
            (conD.Item1, conD.Item2) = (conD.Item2, newD);
            // add k, d
            convergents.Add((conK.Item2, conD.Item2));

            if (conD.Item2 > 1 && conK.Item2 > 1) {
                BigInteger phiNumerator = e * conD.Item2 - 1;
                if (phiNumerator % conK.Item2 == 0) {
                    BigInteger phi = phiNumerator / conK.Item2;

                    BigInteger sumB = n - phi + 1;
                    BigInteger discriminant = sumB * sumB - 4 * n;

                    if (discriminant >= 0) {
                        BigInteger sqrtDisc = NumberTheoryService.IntegerSquareRoot(discriminant);
                        if (sqrtDisc * sqrtDisc == discriminant) {
                            BigInteger p = (sumB + sqrtDisc) / 2;
                            if (p > 1 && n % p == 0) {
                                return new WienerAttackResult(conD.Item2, phi, convergents);
                            }
                        }
                    }
                }
            }
        }

        return null;
    }
}
