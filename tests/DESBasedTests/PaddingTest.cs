
#pragma warning disable CS8625

using DESBased.Core.Padding;

namespace DESBased.Core.Modes.Tests {
public class PaddingProviderTests {

    [Theory]
    [MemberData( nameof(GenData) )]
    public void ApplyValidDataShouldAddCorrectPadding(int blockSize, int dataLength, MyPadding mode) {
        var data = Enumerable.Range(0, dataLength).Select(i => (byte)i).ToArray();
        int expectedPadLength = blockSize - (dataLength % blockSize);
        if (expectedPadLength == blockSize) expectedPadLength = blockSize;

        byte[] pad = PaddingProvider.Apply(data, blockSize, mode);
        byte[] unpadded = PaddingProvider.Remove(pad, mode);
        if (mode is MyPadding.Zeros) {
            if (expectedPadLength == blockSize) Assert.Equal(dataLength + 0, pad.Length);
            else Assert.Equal(dataLength + expectedPadLength, pad.Length);
            if (data.Length != 0) {
                if (data[^1] != 0) Assert.Equal(data, unpadded);
                else Assert.Equal(data[..^1], unpadded);
            }
        } else {
            Assert.Equal(dataLength + expectedPadLength, pad.Length);
            Assert.Equal((byte)expectedPadLength, pad[^1]);
            Assert.Equal(data, unpadded);
        }
    }

    [Theory]
    [MemberData( nameof(GenMode) )]
    public void NullDataShouldThrow(MyPadding mode) {
        Assert.Throws<ArgumentNullException>(() => 
            PaddingProvider.Apply(null, 8, mode));
        Assert.Throws<ArgumentNullException>(() => 
            PaddingProvider.Remove(null, MyPadding.Pkcs7));
    }

    [Theory]
    [MemberData( nameof(GenMode) )]
    public void ApplyInvalidBlockSizeShouldThrow(MyPadding mode) {
        Assert.Throws<ArgumentException>(() => PaddingProvider.Apply([1], 0, mode));
        Assert.Throws<ArgumentException>(() => PaddingProvider.Apply([2, 7], -1, mode));
    }

    [Fact]
    public void ApplyUnsupportedModeShouldThrow() {
        Assert.Throws<NotSupportedException>(() => PaddingProvider.Apply([1], 8, (MyPadding)999));
    }

    [Theory]
    [MemberData( nameof(GenInvalidPad) )]
    public void RemoveInvalidDataShouldThrow(byte[] data, MyPadding mode) {
        Assert.Throws<InvalidOperationException>(() => PaddingProvider.Remove(data, mode));
    }

    [Theory]
    [MemberData( nameof(GenMode) )]
    public void RemoveEmptyDataShouldReturnEmpty(MyPadding mode) {
        Assert.Empty(PaddingProvider.Remove(Array.Empty<byte>(), mode));
    }

    public static IEnumerable<object[]> GenData() {
        /// blockSize dataLength Mode
        var sizes = new[] {
            new { BlockSize = 8, DataLength = 0 },
            new { BlockSize = 8, DataLength = 1 },
            new { BlockSize = 8, DataLength = 7 },
            new { BlockSize = 8, DataLength = 8 },
            new { BlockSize = 8, DataLength = 9 },
            new { BlockSize = 8, DataLength = 15 },
            new { BlockSize = 16, DataLength = 15 }
        };
        var paddingModes = Enum.GetValues<MyPadding>();
        return sizes.SelectMany(size => paddingModes.Select(
            mode => new object[] { size.BlockSize, size.DataLength, mode }));
    }

    public static IEnumerable<object[]> GenMode() {
        return Enum.GetValues<MyPadding>().Select(mode => new object[] { mode });
    }

    public static IEnumerable<object[]> GenInvalidPad() {
        yield return [(byte[])[ 1, 2, 3, 4, 5, 6, 7, 0 ], MyPadding.Pkcs7];
        yield return [(byte[])[ 1, 2, 3, 4, 5, 6, 7, 17 ], MyPadding.Pkcs7];
        yield return [(byte[])[ 1, 2, 3, 4, 5, 3, 2, 3 ], MyPadding.Pkcs7];
        yield return [(byte[])[ 1, 2, 3, 4, 5, 0, 5, 3 ], MyPadding.AnsiX923];
        yield return [(byte[])[ 1, 2, 3, 4, 5, 6, 7, 0 ], MyPadding.AnsiX923];
        yield return [(byte[])[ 1, 2, 3, 4, 5, 6, 7, 0 ], MyPadding.Iso10126];
    }
}
}
