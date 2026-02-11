
using System.Numerics;

namespace Rijndael.Galois.Tests {
public class GF2NCalcTests {

    [Theory]
    [InlineData(0b11001100, 0b10101010, 0b01100110)]
    [InlineData(0xFF, 0xFF, 0x00)]
    [InlineData(0x00, 0xFF, 0xFF)]
    [InlineData(0x57, 0x83, 0xD4)]
    public void AddShouldReturnXor(byte a, byte b, byte expected) => 
        Assert.Equal(expected, GF2NCalc.Add(a, b));

    [Theory]
    [InlineData(0b11001100, 7)]
    [InlineData(0x80, 7)]
    [InlineData(0x01, 0)]
    [InlineData(0x00, -1)]
    [InlineData(0xFF, 7)]
    public void DegreeShouldReturnCorrectDegree(byte f, int expected) =>
        Assert.Equal(expected, GF2NCalc.Degree(f));

    [Theory]
    [InlineData(0x57, 0x83, 0x11B, 0xC1)]
    [InlineData(0x01, 0x01, 0x11B, 0x01)]
    [InlineData(0x00, 0xFF, 0x11B, 0x00)]
    [InlineData(0x02, 0x03, 0x11B, 0x06)]
    [InlineData(0x13, 0x0D, 0x11B, 0xC7)]
    [InlineData(0x01, 0xAB, 0x1B, 0xAB)]
    [InlineData(0xAB, 0x01, 0x1B, 0xAB)]
    public void MulModWithAESPolynomialShouldCalculateCorrectly(
        byte a, byte b, ushort mod, byte expected
    ) => Assert.Equal(expected, GF2NCalc.MulMod(a, b, (byte)mod));

    [Fact]  // x^6 + x^5 + x^3 reducible
    public void MulModWithReduciblePolynomialShouldThrow() =>
        Assert.Throws<ArgumentException>(() => GF2NCalc.MulMod(0x01, 0x01, 0x68, degree8: false));

    [Theory]
    [InlineData(0x01, 0x11B, 0x01)]
    [InlineData(0x02, 0x11B, 0x8D)]
    [InlineData(0x03, 0x11B, 0xF6)]
    [InlineData(0x00, 0x11B, 0x00)]
    [InlineData(0x57, 0x11B, 0xBF)]
    public void InvWithAESPolynomialShouldCalculateCorrectly(byte f, ushort mod, byte expected) {
        if (f == 0) return;
        Assert.Equal(expected, GF2NCalc.Inv(f, (byte)mod));
        Assert.Equal(f, GF2NCalc.Inv(GF2NCalc.Inv(f, (byte)mod), (byte)mod));
    }

    [Fact]
    public void InvWithZeroShouldReturnZero() => Assert.Equal(0, GF2NCalc.Inv(0, 0x1B));

    [Theory]
    [InlineData(0x11BUL)]
    [InlineData(0x11DUL)]
    [InlineData(0x12BUL)]
    public void MulModThenInvShouldReturnOne(ulong mod) {
        if (!GF2NCalc.Irreducible(mod)) return;
        byte value = 0x57, modByte = (byte)(mod & 0xFF);
        Assert.Equal(0x01, GF2NCalc.MulMod(value, GF2NCalc.Inv(value, modByte), modByte));
    }

    [Theory]
    [InlineData(0x11BUL, true)]  // x^8 + x^4 + x^3 + x + 1
    [InlineData(0x11DUL, true)]  // x^8 + x^4 + x^3 + x^2 + 1
    [InlineData(0x12BUL, true)]  // x^8 + x^5 + x^3 + x + 1
    [InlineData(0x12DUL, true)]  // x^8 + x^5 + x^3 + x^2 + 1
    [InlineData(0x169UL, true)]  // x^8 + x^6 + x^5 + x^3 + 1
    [InlineData(0x1F5UL, true)]  // x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1
    [InlineData(0x00UL, false)]  // 0
    [InlineData(0x01UL, false)]  // 1
    [InlineData(0x02UL, true)]  // x
    [InlineData(0x03UL, true)]  // x + 1
    [InlineData(0x107UL, false)]  // x^8 + x^2 + x + 1
    public void IrreducibleShouldIdentifyCorrectly(ulong f, bool expected)
        => Assert.Equal(expected, GF2NCalc.Irreducible(f));

    [Theory]
    [InlineData(0x1B, true)]
    [InlineData(0x1D, true)]
    [InlineData(0x68, false)]
    public void IrreducibleByteOverloadShouldWork(byte f, bool expected)
        => Assert.Equal(expected, GF2NCalc.Irreducible(f, degree8: true));

    [Fact]
    public void IrreduciblesAllPolynomialsShouldBeIrreducible() {
        var irreducibles = GF2NCalc.Irreducibles8();
        Assert.Equal(30, irreducibles.Count);
        foreach (var poly in irreducibles)
            Assert.True(GF2NCalc.Irreducible(poly), $"Полином 0x{poly:X2} должен быть неприводимым");
        Assert.Contains((byte)0x1B, irreducibles);
    }

    [Fact]
    public void FactorizeWithZeroShouldThrow() => Assert.Throws<ArgumentException>(() => GF2NCalc.Factorize(0));

    [Fact]
    public void FactorizeWithOneShouldReturnEmptyList() => Assert.Empty(GF2NCalc.Factorize(1));

    [Fact]
    public void FactorizeWithIrreduciblePolynomialShouldReturnItself() {
        ulong irreducible = 0x11B;
        var factors = GF2NCalc.Factorize(irreducible).ToList();
        Assert.Single(factors);
        Assert.Equal(irreducible, factors.First());
    }

    [Fact]
    public void FactorizeWithReduciblePolynomialShouldReturnCorrectFactors() {
        // Arrange: (x^2 + x + 1) * (x^3 + x + 1) = x^5 + x^4 + 1 = 0x31
        ulong factor1 = 0x7;  // x^2 + x + 1
        ulong factor2 = 0xB;  // x^3 + x + 1
        ulong f = PolyMul(factor1, factor2);  // = 0x31
        var factors = GF2NCalc.Factorize(f).OrderBy(x => x).ToList();
        Assert.Equal(2, factors.Count);
        Assert.Equal(factor1, factors[0]);
        Assert.Equal(factor2, factors[1]);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(7)]
    [InlineData(10)]
    [InlineData(20)]
    [InlineData(30)]
    // [InlineData(50)]  // Too long
    public void FactorizeShouldWorkForRandomPolynomialOfDegree(int degree) {
        var random = new Random(42);
        if (degree >= 64) throw new ArgumentException("Degree must be < 64 for ulong representation.");

        ulong f = 1UL << degree;
        for (int i = 0; i < degree; i++) f |= (ulong)random.Next(2) * (1UL << i);
        var factors = GF2NCalc.Factorize(f).ToList();

        foreach (var factor in factors) Assert.True(GF2NCalc.Irreducible(factor),
            $"Factor 0x{factor:X} is not irreducible (degree={Degree(factor)})");
        ulong product = 1;
        foreach (var factor in factors) product = PolyMul(product, factor);
        Assert.Equal(f, product);
    }

    [Theory]
    [InlineData(0x1BBUL, (ulong[])[0x13, 0x19])]  // (x^4 + x + 1) * (x^4 + x^3 + 1) = x^8 + x^7 + x^5 + x^4 + x^3 + x + 1 = 0x1BB
    [InlineData(0x75UL, (ulong[])[0x75UL])]  // (x^2 + x + 1)^3 = x^6 + x^5 + x^3 + x^2 + 1 = 0x75
    public void FactorizeKnownCompositePolynomials(ulong f, ulong[] expectedFactors) {
        List<ulong> actualFactors = GF2NCalc.Factorize(f)
            .OrderBy(x => x).ThenBy(x => Degree(x)).ToList();

        List<ulong> expectedSorted = expectedFactors.OrderBy(x => x)
            .ThenBy(x => Degree(x)).ToList();

        Assert.Equal(expectedSorted.Count, actualFactors.Count);
        for (int i = 0; i < expectedSorted.Count; i++) Assert.Equal(expectedSorted[i], actualFactors[i]);

        ulong product = 1;
        foreach (var factor in actualFactors) product = PolyMul(product, factor);
        Assert.Equal(f, product);
    }

    private static ulong PolyMul(ulong a, ulong b) {
        ulong result = 0;
        while (b != 0) {
            if ((b & 1) != 0) result ^= a;
            a <<= 1;
            b >>= 1;
        }
        return result;
    }

    private static int Degree(ulong f) =>
        sizeof(ulong) * 8 - 1 - BitOperations.LeadingZeroCount(f);
}
}
