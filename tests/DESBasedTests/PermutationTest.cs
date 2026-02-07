
#pragma warning disable CS8604
#pragma warning disable CS8625

using DESBased.Core.Ciphers.DES;

namespace DESBased.Core.Permutation.Tests {
public class BitPermutationTests {

    [Fact]
    public void PermuteIdentityPermutationShouldReturnInput() {
        byte[] input = { 0b10110010, 0b01101100 };
        byte[] result = Permutation.Permute(input, [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ], false, true);
        Assert.Equal(input, result);  // zero-based
        result = Permutation.Permute(input, [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 ], false, false);
        Assert.Equal(input, result);  // one-based
    }

    [Fact]
    public void PermuteDESInitialPermutationShouldMatchKnownResult() {
        // IP[24] = 64; input[IP[24]] == 1;
        byte[] input = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        var output = Permutation.Permute(input, DESTables.IP, false, false);
        // output[3] == 0x80 (10000000)
        Assert.Equal([ 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00 ], output);
    }

    [Fact]
    public void PermuteCompressingPermutationShouldWork() {
        var output = Permutation.Permute([ 0b10000000, 0x00, 0x00, 0x00 ], [ 2, 4, 6, 8, 10, 12, 14, 16 ], false, true);
        Assert.Equal([ 0x00 ], output);  // Discards odd bits
    }

    [Fact]
    public void PermuteExpandingPermutationShouldWork() {
        byte[] input = { 0b10000000, 0x00, 0x00 }; 
        int[] expand = {
            1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,
            9,9,10,10,11,11,12,12,13,13,14,14,15,15,16,16,
            17,17,18,18,19,19,20,20,21,21,22,22,23,23,24,24
        }; // one-based
        var output = Permutation.Permute(input, expand, false, false);
        // output[0] = 0b11000000 = 0xC0
        Assert.Equal([ 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00 ], output);
    }

    [Theory]
    [MemberData( nameof(Flags) )]
    public void PermuteEmptyShouldReturnEmptyArray(bool order, bool zeroStart) {
        var result = Permutation.Permute(Array.Empty<byte>(), Array.Empty<int>(), order, zeroStart);
        Assert.Empty(result);
        result = Permutation.Permute([ 0xFF ], Array.Empty<int>(), order, zeroStart);
        Assert.Empty(result);
    }

    [Fact]
    public void PermuteSingleBitInputAndOutputShouldWork() {
        var result = Permutation.Permute([ 0b10000000 ], [ 1 ], false, false);
        Assert.Equal([ 0b10000000 ], result); // 1 bit -> 1 byte with MSB=1
        result = Permutation.Permute([ 0b10000000 ], [ 0 ], false, true);
        Assert.Equal([ 0b10000000 ], result); // 1 bit -> 1 byte with MSB=1
    }

    [Fact]
    public void PermuteIndexOutOfRangeShouldThrowr() {
        Assert.Throws<IndexOutOfRangeException>(() =>
            Permutation.Permute([ 0xFF ], [8], false, true)
        );
        Assert.Throws<IndexOutOfRangeException>(() =>
            Permutation.Permute([ 0xFF ], [9], false, false)
        );
        Assert.Throws<IndexOutOfRangeException>(() =>
            Permutation.Permute([ 0xFF ], [0], false, false)
        );
        Assert.Throws<IndexOutOfRangeException>(() =>
            Permutation.Permute([ 0xFF ], [-1], false, true)
        );
    }

    [Fact]
    public void PermuteBitOrderWithinByteShouldTreatLeftmostAsMSB() {
        byte[] output = Permutation.Permute([ 0b10000000 ], [ 8, 2, 3, 4, 5, 6, 7, 1 ], false, false);
        Assert.Equal([ 0b00000001 ], output);  // swap(1, 8)
    }

    [Theory]
    [MemberData(nameof(Flags))]
    public void PermuteNullInputOrPermutationShouldThrow(bool order, bool zeroStart) {
        Assert.Throws<ArgumentNullException>(() => Permutation.Permute(null, [1], order, zeroStart));
        Assert.Throws<ArgumentNullException>(() => Permutation.Permute([ 0xFF ], null, order, zeroStart));
    }

    [Fact]
    public void PermuteFullReversalShouldReverseBits() {
        byte[] result = Permutation.Permute([ 0b00000001 ], [ 1, 2, 3, 4, 5, 6, 7, 8 ], true, false);
        Assert.Equal(new byte[]{0b00000001}, result);
    }

    public static IEnumerable<object[]> Flags(){
        yield return [ false, false ];
        yield return [ false, true ];
        yield return [ true, false ];
        yield return [ true, true ];
    }
}
}
