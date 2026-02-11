
using System.Numerics;

namespace Rijndael.Galois {
public static class GF2NCalc {

    public static int Degree(byte f) => Degree((ulong)f);

    public static byte Add(byte a, byte b) => (byte)(a ^ b);

    public static bool Irreducible(byte f, bool degree8=true) => Irreducible((ulong)(f | (degree8 ? 0x100: 0)));

    public static byte MulMod(byte a, byte b, byte mod=0, bool degree8=true) {
        ushort modU = (ushort)(mod | (degree8 ? 0x100: 0));
        if (!Irreducible(modU)) throw new ArgumentException("Modulus may not be reducible");
        return (byte)MulMod(a, b, modU);
    }

    public static byte Inv(byte f, byte mod, bool degree8=true) {
        ushort modU = (ushort)(mod | (degree8 ? 0x100: 0));
        if (!Irreducible(modU)) throw new ArgumentException("Modulus may not be reducible");
        // FIPS.197 b^254 = b^-1
        return (byte)(f == 0? 0: PowMod(f, 254, modU));
    }

    public static ICollection<byte> Irreducibles8() => Irreducibles(8).Select(x => (byte)x).ToList();

    public static ICollection<ulong> Factorize(ulong f) {
        if (f == 0) throw new ArgumentException("Cannot factor zero");
        if (f == 1) return new List<ulong>();

        List<ulong> factors = new List<ulong>();
        int maxDegree = Degree(f) / 2;

        for (int d = 1; d <= maxDegree; d++) {
            foreach (ulong p in Irreducibles(d)) {
                DivResult divRes;
                while ((divRes = Div(f, p)).remainder == 0) {
                    factors.Add(p);
                    f = divRes.quotient;
                }
            }
        }
        if (f > 1) factors.Add(f);
        return factors;
    }

    //https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Rabin.27s_test_of_irreducibility
    public static bool Irreducible(ulong f) {
        int n = Degree(f);
        if (n <= 0) return false;
        if (n == 1) return true;
        if ((f & 1) == 0) return false;
        const int x = 0b10;
        int k = n;

        for (int p = 2; p * p <= k; p++) {
            if (k % p != 0) continue;

            ulong h = Pow2Mod(x, n / p, f) ^ x;
            if (Euclid(f, h).GCD != 1) return false;
            while (k % p == 0) k /= p;
        }

        if (k > 1) {
            ulong h = Pow2Mod(x, n / k, f) ^ x;
            if (Euclid(f, h).GCD != 1) return false;
        }

        // At last, check that x^(q^n) == x.
        return Pow2Mod(x, n, f) == x;
    }

    /// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    private static ulong MulMod(ulong a, ulong b, ulong mod) {
        if (mod == 0) throw new ArgumentException("Modulus cannot be zero.");
        int n = Degree(mod);
        if (n <= 0) throw new ArgumentException("Modulus must have degree ≥ 1.");
        // Reduction polynomial = mod without the leading x^n term
        ulong reductionPoly = mod ^ (1UL << n);
        ulong result = 0;
        // Process each bit of b (up to n bits; higher bits are irrelevant since a is reduced mod x^n)
        // We iterate over all bits up to max(Degree(a), Degree(b))
        for (int i = 0; i < n; i++) {
            // Add current shifted a to result
            if ((b & (1UL << i)) != 0) result ^= a;
            // Prepare a for next iteration: multiply by x (i.e., shift left 1)
            // Check if highest bit of a (bit n-1) is set -> will overflow to x^n on shift
            bool carry = (a & (1UL << (n - 1))) != 0;
            a <<= 1;
            a &= (1UL << n) - 1; // Keep only lower n bits (mask out x^n and above)
            // Reduce: subtract (XOR) reductionPoly (since x^n ≡ reductionPoly mod mod)
            if (carry) a ^= reductionPoly;
        }
        return result;
    }

/////////////////////////////////////////////////////////////////////////
    private static int Degree(ulong f) =>
        sizeof(ulong) * 8 - 1 - BitOperations.LeadingZeroCount(f);

    private static DivResult Div(ulong a, ulong b) {
        ulong q = 0;
        while (Degree(a) >= Degree(b)) {
            int lead = Degree(a) - Degree(b);
            q ^= 1UL << lead;
            a ^= b << lead;
        }
        return new DivResult(q, a);
    }
    private record DivResult(ulong quotient, ulong remainder);


    private static ulong PowMod(ulong f, ulong exp, ulong mod) {
        if (exp == 0) return 1;
        if (f == 0) return 0;

        ulong result = 1;
        ulong baseVal = f;

        while (exp > 0) {
            if ((exp & 1) == 1) result = MulMod(result, baseVal, mod);
            baseVal = MulMod(baseVal, baseVal, mod);
            exp >>= 1;
        }
        return result;
    }

    private static ulong Pow2Mod(ulong f, int exp, ulong mod)  {
        ulong result = f;
        // f^(2^exp) = f возводится в квадрат exp раз
        for (int i = 0; i < exp; i++) result = MulMod(result, result, mod);
        return result;
    }

    /// <summary>
    /// a*s + b*t = GCD(a, b)
    /// </summary>
    private static EuclidRes Euclid(ulong a, ulong b) {
        ulong r0 = a, r1 = b;
        ulong s0 = 1, s1 = 0;
        ulong t0 = 0, t1 = 1;

        while (r1 != 0) {
            int degR0 = Degree(r0);
            int degR1 = Degree(r1);
            
            if (degR0 < degR1) {
                (r0, r1) = (r1, r0);
                (s0, s1) = (s1, s0);
                (t0, t1) = (t1, t0);
                continue;
            }

            int shift = degR0 - degR1;
            ulong r2 = r0 ^ (r1 << shift);
            ulong s2 = s0 ^ (s1 << shift);
            ulong t2 = t0 ^ (t1 << shift);
            
            r0 = r1; r1 = r2;
            s0 = s1; s1 = s2;
            t0 = t1; t1 = t2;
        }
        return new EuclidRes(r0, s0, t0);
    }
    private record EuclidRes(ulong GCD, ulong S, ulong T);


    private static ICollection<ulong> Irreducibles(int degree) =>
        Enumerable.Range(1 << degree, 1 << degree)
            .Select(x => (ulong)x).Where(Irreducible).ToList();
}
}
