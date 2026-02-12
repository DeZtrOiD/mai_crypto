
using Rijndael.Utils;
using Rijndael.Galois;

namespace Rijndael.Tests {
public class RijndaelHelperTests {

    [Theory]
    [InlineData(128, 4, 128, 4, 10)]
    [InlineData(128, 4, 192, 6, 12)]
    [InlineData(128, 4, 256, 8, 14)]
    [InlineData(192, 6, 128, 4, 12)]
    [InlineData(256, 8, 256, 8, 14)]
    public void GetNrNkNbValidSizesReturnsCorrect(
        int blockSize, int expectedNb, int keySize, int expectedNk, int expectedNr
    ) {
        Assert.Equal(expectedNk, RijndaelHelper.GetNk((ushort)keySize));
        Assert.Equal(expectedNb, RijndaelHelper.GetNb((ushort)blockSize));
        Assert.Equal(expectedNr, RijndaelHelper.GetNr(RijndaelHelper.GetNb((ushort)blockSize), RijndaelHelper.GetNk((ushort)keySize)));
    }

    [Theory]
    [InlineData(0x1B, 0, 1)]
    [InlineData(0x1B, 1, 2)]
    [InlineData(0x1B, 2, 4)]
    [InlineData(0x1B, 3, 8)]
    [InlineData(0x1B, 4, 0x10)]
    public void GetRconValuesCorrectlyDoubled(byte mod, int index, byte expected) {
        var rcon = RijndaelHelper.GetRcon((ushort)(index + 1), mod);
        Assert.Equal(expected, rcon[index]);
    }

    [Theory]
    [MemberData(nameof(NbValues))]
    public void ShiftRowForwardThenInverseReturnsOriginal(ushort Nb) {
        int length = Nb * 4;
        byte[] original = new byte[length];
        for (int i = 0; i < length; i++) original[i] = (byte)i;

        byte[] state = (byte[])original.Clone();
        var shifted = RijndaelHelper.ShiftRow(state, Nb, inverse: false);
        var restored = RijndaelHelper.ShiftRow(shifted, Nb, inverse: true);
        Assert.Equal(original, restored);
        Assert.Same(state, shifted);
        Assert.Same(state, restored);
        for (int col = 0; col < Nb; col++) Assert.Equal(original[4 * col], state[4 * col]);
    }

    [Theory]
    [MemberData(nameof(NbValues))]
    public void AddRoundKeyXorOperationWorksCorrectly(ushort Nb) {
        int length = Nb * 4;
        byte[] state = new byte[length];
        byte[] key = new byte[length];
        for (int i = 0; i < length; i++) {
            state[i] = (byte)i;
            key[i] = (byte)(i * 2);
        }
        byte[] original = (byte[])state.Clone();

        var result = RijndaelHelper.AddRoundKey(state, Nb, key, Nb);
        result = RijndaelHelper.AddRoundKey(result, Nb, key, Nb);
        Assert.Same(state, result);
        Assert.Equal(original, state);
    }

    [Theory]
    [InlineData(4, 6)]
    [InlineData(6, 4)]
    [InlineData(8, 4)]
    public void AddRoundKeyDifferentNbNkThrows(ushort Nb, ushort Nk) =>
        Assert.Throws<ArgumentException>(() => RijndaelHelper.AddRoundKey(new byte[Nb * 4], Nb, new byte[Nk * 4], Nk));

    [Theory]
    [MemberData(nameof(NbValues))]
    public void MixColumnsForwardThenInverseReturnsOriginal(ushort Nb) {
        int length = Nb * 4;
        byte[] original = new byte[length];
        for (int i = 0; i < length; i++) original[i] = (byte)((i * 17 + 13) % 256);
        byte[] state = (byte[])original.Clone();

        var mixed = RijndaelHelper.MixColumns(state, Nb, 0x1B, inverse: false);
        var restored = RijndaelHelper.MixColumns(mixed, Nb, 0x1B, inverse: true);

        Assert.Equal(original, restored);
        Assert.Same(state, mixed);
        Assert.Same(state, restored);
    }

    [Fact]
    public void MixColumnsKnownTestVectorReturnsCorrectResult() {
        byte[] state = new byte[16];
        state[0] = 0xdb; state[1] = 0x13;
        state[2] = 0x53; state[3] = 0x45;
        byte[] expected = (byte[])state.Clone();
        byte[] stateInv = (byte[])state.Clone();
        expected[0] = 0x8e; expected[1] = 0x4d;
        expected[2] = 0xa1; expected[3] = 0xbc;
        Assert.Equal(expected, RijndaelHelper.MixColumns(state, 4));
        Assert.Equal(stateInv, RijndaelHelper.MixColumns(expected, 4, inverse: true));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(8)]
    [InlineData(44)]
    public void leftShiftShiftsBytesLeft(int cols) {
        int length = cols * 4;
        byte[] words = new byte[length];
        for (int i = 0; i < length; i++) words[i] = (byte)i;
        byte[] original = (byte[])words.Clone();
        var result = RijndaelHelper.leftShift(words, (ushort)cols);
        for (int col = 0; col < cols; col++) {
            int baseIdx = col * 4;
            Assert.Equal(original[baseIdx + 1], words[baseIdx]);
            Assert.Equal(original[baseIdx + 2], words[baseIdx + 1]);
            Assert.Equal(original[baseIdx + 3], words[baseIdx + 2]);
            Assert.Equal(original[baseIdx + 0], words[baseIdx + 3]);
        }
        Assert.Same(words, result);
    }

    [Theory]
    [MemberData(nameof(NbValues))]
    public void SubWordsForwardThenInverseReturnsOriginal(ushort Nb) {
        int length = Nb * 4;
        byte[] original = new byte[length];
        for (int i = 0; i < length; i++) original[i] = (byte)((i * 17 + 13) % 256);
        
        byte[] sbox = (byte[])_sbox.Clone();
        byte[] invSbox = (byte[])_invSbox.Clone();
        byte[] state = (byte[])original.Clone();

        var substituted = RijndaelHelper.SubWords(state, Nb, sbox, invSbox, inverse: false, sboxInitiated: true);
        var restored = RijndaelHelper.SubWords(substituted, Nb, sbox, invSbox, inverse: true, sboxInitiated: true);

        Assert.Equal(original, restored);
        Assert.Same(state, substituted);
        Assert.Same(state, restored);
    }

    [Fact]
    public void SubWordsSboxInitiatedFalseInitializesZero() {
        ushort Nb = 4;
        int length = Nb * 4;
        byte[] state = new byte[length];
        state[0] = 0x00;
        byte[] sbox = new byte[256];
        byte[] invSbox = new byte[256];

        RijndaelHelper.SubWords(state, Nb, sbox, invSbox, inverse: false, sboxInitiated: false);

        Assert.NotEqual(0, sbox[0]);
        Assert.Equal(0, invSbox[sbox[0]]);
        Assert.Equal(sbox[0], state[0]);
    }

    [Theory]
    [InlineData(128, true)]
    [InlineData(192, true)]
    [InlineData(256, true)]
    [InlineData(0, false)]
    [InlineData(64, false)]
    [InlineData(160, false)]
    [InlineData(512, false)]
    public void IsValidBlockSizeVariousInputsReturnsCorrect(int size, bool expected) =>
        Assert.Equal(expected, RijndaelHelper.IsValidBlockSize(size));

    [Theory]
    [InlineData(128, true)]
    [InlineData(192, true)]
    [InlineData(256, true)]
    [InlineData(0, false)]
    [InlineData(64, false)]
    [InlineData(160, false)]
    [InlineData(512, false)]
    public void IsValidKeySizeVariousInputsReturnsCorrect(int size, bool expected) =>
        Assert.Equal(expected, RijndaelHelper.IsValidKeySize(size));

    [Theory]
    [InlineData(4, true)]
    [InlineData(6, true)]
    [InlineData(8, true)]
    [InlineData(5, false)]
    [InlineData(7, false)]
    [InlineData(10, false)]
    public void IsValidNBValidatesCorrectly(ushort Nb, bool expected) =>
        Assert.Equal(expected, RijndaelHelper.IsValidNB(Nb));

    [Theory]
    [InlineData(4, true)]
    [InlineData(6, true)]
    [InlineData(8, true)]
    [InlineData(5, false)]
    [InlineData(7, false)]
    [InlineData(10, false)]
    public void IsValidNKValidatesCorrectly(ushort Nk, bool expected) => Assert.Equal(expected, RijndaelHelper.IsValidNK(Nk));

    public static IEnumerable<object[]> NbValues =>
        (object[][])[[(ushort)4], [(ushort)6], [(ushort)8]];
    private byte[] _sbox;
    private byte[] _invSbox;
    public RijndaelHelperTests() => (_sbox, _invSbox) = CreateTestSboxes();
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
