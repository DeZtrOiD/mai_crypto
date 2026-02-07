
#pragma warning disable CS8625
#pragma warning disable xUnit1026

namespace DESBased.Core.Utils.Tests {
public class ByteUtilsTests {
    [Theory]
    [MemberData(nameof(XorData))]
    public void XorShouldProduceCorrectResult(byte[] res, byte[] a, byte[] b) {
        Assert.Equal(res, ByteUtils.Xor(a, b));
    }

    [Fact]
    public void XorNullArraysShouldThrow() {
        Assert.Throws<ArgumentNullException>(() => ByteUtils.Xor(null!, new byte[1]));
        Assert.Throws<ArgumentNullException>(() => ByteUtils.Xor(new byte[1], null!));
    }

    [Theory]
    [MemberData(nameof(ConcatData))]
    public void ConcatShouldProduceCorrectResult(byte[][] input, byte[] res) {
        Assert.Equal(res, ByteUtils.Concat(input));
    }

    [Fact]
    public void ConcatNullArrayShouldThrow() {
        Assert.Throws<ArgumentNullException>(() => ByteUtils.Concat(null));
    }

    [Theory]
    [MemberData(nameof(SplitData))]
    public void SplitCorrectResult(byte[] input, int blockSize, byte[][] res) {
        Assert.Equal(res, ByteUtils.Split(input, blockSize));
    }

    [Fact]
    public void SplitShouldThrow() {
        Assert.Throws<ArgumentNullException>(() => ByteUtils.Split(null!, 8));
        Assert.Throws<ArgumentException>(() => ByteUtils.Split(new byte[16], 0));
        Assert.Throws<ArgumentException>(() => ByteUtils.Split(new byte[16], -1));
    }

    [Theory]
    [MemberData(nameof(SplitData))]
    public void SplitIntoBlocksThenConcatBlocksShouldPreserveData(byte[] input, int blockSize, byte[][] res) {
            Assert.Equal(input, ByteUtils.Concat(ByteUtils.Split(input, blockSize)));
    }

    [Theory]
    [MemberData(nameof(AddBigEndianData))]
    public void AddBigEndianCorrectResult(byte[] input, ulong value, byte[] result) {
        Assert.Equal(result, ByteUtils.AddBigEndian2pow8(input, value));
    }

    [Fact]
    public void AddCounterTooSmallBlockShouldThrow() {
        Assert.Throws<ArgumentException>(() => ByteUtils.AddBigEndian2pow8([ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ], 1));
    }

    [Theory]
    [MemberData(nameof(AddBigEndianData))]
    public void CounterOperationsRoundTripShouldPreserveValue(byte[] input, ulong value, byte[] result) {
        byte[] original = (byte[])input.Clone();
        Assert.Equal(
            original,
            ByteUtils.AddBigEndian2pow8(ByteUtils.AddBigEndian2pow8(input, value), ulong.MaxValue - (value - 1))
        );
    }

    [Theory]
    [MemberData(nameof(AddModData))]
    public void AddModCorrectResult(byte[] a, byte[] b, byte[] result) {
        Assert.Equal(result, ByteUtils.AddMod2N( a, b ));
    }

    [Fact]
    public void AddModDifferentBlockSizesShouldThrow() {
        Assert.Throws<ArgumentException>(() => ByteUtils.AddMod2N([ 0x01, 0x02, 0x03 ], [ 0x04, 0x05 ]));
    }

    [Theory]
    [MemberData(nameof(MultiplyModuloData))]
    public void MultiplyModuloCorrectResult(byte[] value, uint multiplier, byte[] result) {
        Assert.Equal(result, ByteUtils.MultiplyMod2N(value, multiplier));
    }

    [Fact]
    public void MultiplyModuloNullValueShouldThrow() {
        Assert.Throws<ArgumentNullException>(() => ByteUtils.MultiplyMod2N(null, 0));
    }

    [Theory]
    [MemberData(nameof(MultiplyModuloData))]
    public void AddModuloThenMultiplyModuloShouldBeAssociative(byte[] a, uint c, byte[] b) {
        // (a + b) * c == a * c + b * c (mod 2N)
        if (a.Length != b.Length) return;
        Assert.Equal(
            ByteUtils.MultiplyMod2N(ByteUtils.AddMod2N(a, b), c),
            ByteUtils.AddMod2N(ByteUtils.MultiplyMod2N(a, c), ByteUtils.MultiplyMod2N(b, c))
        );
    }

    public static IEnumerable<object[]> XorData() {
        // expected, a, b
        yield return [ (byte[])[ 0x05, 0x07, 0x05 ], (byte[])[ 0x01, 0x02, 0x03 ],(byte[])[ 0x04, 0x05, 0x06 ] ];
        yield return [ (byte[])[ 0x0B, 0x09, 0x0F ], (byte[])[ 0x0A, 0x0B, 0x0C ], (byte[])[ 0x01, 0x02, 0x03, 0x04, 0x05 ] ];
        yield return [ (byte[])[ 0x00, 0x00, 0x00, 0x00 ], (byte[])[ 0x01, 0x02, 0x03, 0xFF ], (byte[])[ 0x01, 0x02, 0x03, 0xFF ] ];
        yield return [ Array.Empty<byte[]>(), Array.Empty<byte>(), Array.Empty<byte[]>() ];
    }

    public static IEnumerable<object[]> ConcatData() {
        // input, expected
        yield return [ (byte[][])[ [ 0x01, 0x02, 0x03 ] ], (byte[])[ 0x01, 0x02, 0x03 ] ];
        yield return [ (byte[][])[ [ 0x01, 0x02 ], [ 0x03, 0x04, 0x05 ], [ 0x06 ]], (byte[])[ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 ] ];
        yield return [ (byte[][])[ [ 0x01 ], [ 0x02 ] ], (byte[])[ 0x01, 0x02 ] ];
        yield return [ Array.Empty<byte[]>(), Array.Empty<byte>() ];
    }
    
    public static IEnumerable<object[]> SplitData() {
        // input, blockSize, result
        yield return [ Array.Empty<byte>(), 8, Array.Empty<byte[]>() ];
        byte[] data = Enumerable.Range(0, 24).Select(i => (byte)i).ToArray();
        
        yield return [ data, 8, (byte[][])[ data[..8], data[8..16], data[16..24] ] ];
        data = Enumerable.Range(0, 17).Select(i => (byte)i).ToArray();
        
        yield return [ data, 8, (byte[][])[ data[..8], data[8..16], data[16..17] ] ];
        yield return [ (byte[])[0x42], 16, (byte[][])[ [ 0x42 ] ] ];
    }

    public static IEnumerable<object[]> AddBigEndianData() {
        // input, value, result
        yield return [ (byte[]) [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ], 1ul,
            (byte[])[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 ] ];
        yield return [ (byte[])[ 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF ], 1ul,
            (byte[])[ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 ] ];
        yield return [ new byte[8], 0x123456789ABCDEF0ul, (byte[])[ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 ] ];
        yield return [ (byte[])[ 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ], 2ul,
            (byte[])[ 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 ] ];
        yield return [ new byte[8], 0xFFFFFFFFFFFFFFFFul, (byte[])[ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ] ];
        yield return [ (byte[])[ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ], 0x1ul, new byte[8] ];
    }

    public static IEnumerable<object[]> AddModData() {
        // a + b = result
        yield return [ (byte[])[ 0x00, 0x00, 0x00, 0x05 ], (byte[])[ 0x00, 0x00, 0x00, 0x03 ], (byte[])[ 0x00, 0x00, 0x00, 0x08 ] ];
        yield return [ (byte[])[ 0x00, 0x00, 0x00, 0x01 ], (byte[])[ 0x00, 0x00, 0xFF, 0xFF ], (byte[])[ 0x00, 0x01, 0x00, 0x00 ] ];
        yield return [ (byte[])[ 0xFF, 0xFF, 0xFF, 0xFF ], (byte[])[ 0x00, 0x00, 0x00, 0x01 ], (byte[])[ 0x00, 0x00, 0x00, 0x00 ] ];
        yield return [ (byte[])[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ],
            (byte[])[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 ],
            (byte[])[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 ] ];
        yield return [ (byte[])[ 0x01, 0xFF, 0xFF, 0xFF ], (byte[])[ 0x00, 0x00, 0x00, 0x01 ], (byte[])[ 0x02, 0x00, 0x00, 0x00 ] ];
        yield return [ (byte[])[0x12, 0x34, 0x56, 0x78], new byte[ 4 ], (byte[])[0x12, 0x34, 0x56, 0x78] ];
    }

    public static IEnumerable<object[]> MultiplyModuloData() {
        // input, value, result
        yield return [ (byte[]) [ 0x12, 0x34, 0x56, 0x78 ], 0u, new byte[4] ];
        yield return [ (byte[])[ 0x12, 0x34, 0x56, 0x78 ], 1u, (byte[])[ 0x12, 0x34, 0x56, 0x78 ] ];
        yield return [ (byte[])[ 0x00, 0x00, 0x00, 0x05 ], 3u, (byte[])[ 0x00, 0x00, 0x00, 0x0F ] ];
        yield return [ (byte[])[ 0x00, 0x00, 0x00, 0xFF ], 2u, (byte[])[ 0x00, 0x00, 0x01, 0xFE ] ];
        yield return [ (byte[])[ 0xFF, 0xFF, 0xFF, 0xFF ], 2u, (byte[])[ 0xFF, 0xFF, 0xFF, 0xFE ] ];
        yield return [ (byte[])[ 0x00, 0x00, 0x00, 0x01 ], 0x12345u, (byte[])[ 0x00, 0x01, 0x23, 0x45 ] ];
        yield return [ (byte[])[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 ], uint.MaxValue, (byte[])[ 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFE ] ];
    }
}
}
