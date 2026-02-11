
#pragma warning disable CS8600
#pragma warning disable CS8601
#pragma warning disable CS8604

using Rijndael.Utils;
using Rijndael.Galois;

namespace Rijndael.Tests {
public class RijndaelRoundFunctionTests {

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    [InlineData(8, false)]
    [InlineData(8, true)]
    public void ConstructorValidParametersCreatesInstance(ushort Nk, bool inverse) {
        var (sbox, invSbox) = CreateTestSboxes();
        Assert.NotNull(new RijndaelRoundFunction(Nk, 0x1B, ref sbox, ref invSbox, inverse));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void ConstructorNullSboxOrInvSboxThrowsArgumentNullException(bool nullSbox, bool nullInvSbox) {
        byte[] sbox = nullSbox ? null : new byte[256];
        byte[] invSbox = nullInvSbox ? null : new byte[256];
        Assert.Throws<ArgumentNullException>(() => new RijndaelRoundFunction(4, 0x1B, ref sbox, ref invSbox));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(16)]
    public void ConstructorInvalidBlockSizeThrowsArgumentException(ushort invalidNb) {
        var (sbox, invSbox) = CreateTestSboxes();
        Assert.Throws<ArgumentException>(() => new RijndaelRoundFunction(invalidNb, 0x1B, ref sbox, ref invSbox));
    }

    [Theory]
    [InlineData(128)]
    [InlineData(255)]
    [InlineData(257)]
    public void ConstructorWrongSboxSizeThrowsArgumentException(int sboxSize) {
        byte[] sbox = new byte[sboxSize];
        byte[] invSbox = new byte[256];
        Assert.Throws<ArgumentException>(() =>
            new RijndaelRoundFunction(4, 0x1B, ref sbox, ref invSbox));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(8)]
    public void TransformValidInputReturnsSameLength(ushort Nb) {
        var (sbox, invSbox) = CreateTestSboxes();
        var roundFunction = new RijndaelRoundFunction(Nb, 0x1B, ref sbox, ref invSbox);
        int byteSize = Nb * 4;
        byte[] input = new byte[byteSize];
        byte[] key = new byte[byteSize];
        new Random(42).NextBytes(input);
        new Random(43).NextBytes(key);
        
        var result = roundFunction.Transform(input, key);
        Assert.Equal(byteSize, result.Length);
    }

    [Theory]
    [InlineData(true, false)]  // null input
    [InlineData(false, true)]  // null key
    public void TransformNullInputOrKeyThrowsArgumentNullException(bool nullInput, bool nullKey) {
        var (sbox, invSbox) = CreateTestSboxes();
        var roundFunction = new RijndaelRoundFunction(4, 0x1B, ref sbox, ref invSbox);
        byte[] input = nullInput ? null : new byte[16];
        byte[] key = nullKey ? null : new byte[16];
        
        Assert.Throws<ArgumentNullException>(() => roundFunction.Transform(input, key));
    }

    [Theory]
    [InlineData(4, 15, false)]
    [InlineData(4, 17, false)]
    [InlineData(4, 15, true)]
    [InlineData(4, 17, true)]
    [InlineData(6, 23, false)]
    [InlineData(6, 25, false)]
    [InlineData(6, 23, true)]
    [InlineData(6, 25, true)]
    [InlineData(8, 31, false)]
    [InlineData(8, 33, false)]
    [InlineData(8, 31, true)]
    [InlineData(8, 33, true)]
    public void TransformWrongLengthThrowsArgumentException(ushort Nb, int wrongLength, bool isKey) {
        var (sbox, invSbox) = CreateTestSboxes();
        var roundFunction = new RijndaelRoundFunction(Nb, 0x1B, ref sbox, ref invSbox);
        int correctSize = Nb * 4;
        byte[] input = isKey ? new byte[correctSize] : new byte[wrongLength];
        byte[] key = isKey ? new byte[wrongLength] : new byte[correctSize];
        Assert.Throws<ArgumentException>(() => roundFunction.Transform(input, key));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(8)]
    public void TransformForwardThenInverseReturnsOriginal(ushort Nb) {
        var (sbox, invSbox) = CreateTestSboxes();
        int byteSize = Nb * 4;
        var forward = new RijndaelRoundFunction(Nb, 0x1B, ref sbox, ref invSbox, false);
        var inverse = new RijndaelRoundFunction(Nb, 0x1B, ref sbox, ref invSbox, true);
        
        byte[] original = new byte[byteSize];
        byte[] key = new byte[byteSize];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(original);
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
        
        var transformed = forward.Transform((byte[])original.Clone(), key);
        var recovered = inverse.Transform((byte[])transformed.Clone(), key);
        Assert.Equal(original, recovered);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(8)]
    public void TransformDifferentInputsOrKeysProduceDifferentOutputs(ushort Nb) {
        var (sbox, invSbox) = CreateTestSboxes();
        int byteSize = Nb * 4;
        var rf = new RijndaelRoundFunction(Nb, 0x1B, ref sbox, ref invSbox);

        byte[] input1 = new byte[byteSize], input2 = new byte[byteSize], key = new byte[byteSize];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(input1);
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(input2);
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
        Assert.NotEqual(rf.Transform((byte[])input1.Clone(), key), rf.Transform((byte[])input2.Clone(), key));
        
        byte[] input = new byte[byteSize], key1 = new byte[byteSize], key2 = new byte[byteSize];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(input);
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key1);
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key2);
        Assert.NotEqual(rf.Transform((byte[])input.Clone(), key1), rf.Transform(input, key2));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(8)]
    public void TransformZeroInputOrKeyProducesNonTrivialOutput(ushort Nb) {
        var (sbox, invSbox) = CreateTestSboxes();
        int byteSize = Nb * 4;
        var rf = new RijndaelRoundFunction(Nb, 0x1B, ref sbox, ref invSbox);

        byte[] input = new byte[byteSize], zeroKey = new byte[byteSize];
        Array.Fill(input, (byte)0xFF);
        Assert.NotEqual(input, rf.Transform((byte[])input.Clone(), zeroKey));

        byte[] zeroInput = new byte[byteSize], key = new byte[byteSize];
        Array.Fill(key, (byte)0xFF);
        Assert.NotEqual(zeroInput, rf.Transform((byte[])zeroInput.Clone(), key));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(8)]
    public void TransformDeterministicSameInputSameOutput(ushort Nb) {
        var (sbox, invSbox) = CreateTestSboxes();
        int byteSize = Nb * 4;
        var rf = new RijndaelRoundFunction(Nb, 0x1B, ref sbox, ref invSbox);
        byte[] input = new byte[byteSize], key = new byte[byteSize];
        new Random(42).NextBytes(input);
        new Random(43).NextBytes(key);
        var r1 = rf.Transform((byte[])input.Clone(), key);
        var r2 = rf.Transform((byte[])input.Clone(), key);
        Assert.Equal(r1, r2);
    }

    [Fact]
    public void TransformAesKnownVectorProducesCorrectResult() {
        var (sbox, invSbox) = CreateTestSboxes();
        var forward = new RijndaelRoundFunction(4, 0x1B, ref sbox, ref invSbox, false);
        var inverse = new RijndaelRoundFunction(4, 0x1B, ref sbox, ref invSbox, true);
        byte[] roundKey1 = {
            0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1,
            0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05
        };
        byte[] plaintext = [
            0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b,
            0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08 
        ];
        byte[] expected = {
            0xa4, 0x9c, 0x7f, 0xf2, 0x68, 0x9f, 0x35, 0x2b,
            0x6b, 0x5b, 0xea, 0x43, 0x02, 0x6a, 0x50, 0x49
        };
        var transformed = forward.Transform((byte[])plaintext.Clone(), roundKey1);
        var decrypted = inverse.Transform((byte[])transformed.Clone(), roundKey1);
        Assert.Equal(plaintext, decrypted);
        Assert.Equal(expected, transformed);
    }

    private static (byte[] sbox, byte[] invSbox) CreateTestSboxes(byte mod = 0x1B) {
        byte[] sbox = new byte[256];
        byte[] invSbox = new byte[256];
        byte sboxValue = RijndaelHelper.AffineTransform(GF2NCalc.Inv(0, mod));
        sbox[0] = sboxValue;
        invSbox[sboxValue] = 0;
        byte invValue = GF2NCalc.Inv(RijndaelHelper.InverseAffineTransform(0), mod);
        invSbox[0] = invValue;
        sbox[invValue] = 0;
        return (sbox, invSbox);
    }
}
}
