
#pragma warning disable CS8600
#pragma warning disable CS8601
#pragma warning disable xUnit1026

using Rijndael.Galois;
using Rijndael.Utils;

namespace Rijndael.Tests {
public class RijndaelKeyScheduleTests {
    [Theory]
    [MemberData(nameof(TestKey128Data))]
    [MemberData(nameof(TestKey192Data))]
    [MemberData(nameof(TestKey256Data))]
    public void GenerateRoundKeysKnownKeysProducesCorrectRoundKeys(
        ushort Nk, byte[] key, int roundIndex, byte[] expectedRoundKey
    ) {
        var (sbox, invSbox) = CreateSboxes();
        var keySchedule = new RijndaelKeySchedule(0x1B, ref sbox, ref invSbox, Nk, 4);
        var roundKeys = keySchedule.GenerateRoundKeys(key);
        Assert.NotNull(roundKeys);
        Assert.True(roundKeys.Length > 0);
        Assert.Equal(expectedRoundKey, roundKeys[roundIndex]);
    }

    [Theory]
    [InlineData(128, 4, 11)]
    [InlineData(192, 6, 13)]
    [InlineData(256, 8, 15)]
    public void GenerateRoundKeysCorrectNumberOfRounds(int keySize, ushort Nk, int expectedRounds) {
        var (sbox, invSbox) = CreateSboxes();
        byte[] key = new byte[Nk * 4];
        new Random(42).NextBytes(key);
        var keySchedule = new RijndaelKeySchedule(0x1B, ref sbox, ref invSbox, Nk, 4);
        var roundKeys = keySchedule.GenerateRoundKeys(key);
        Assert.Equal(expectedRounds, keySchedule.GenerateRoundKeys(key).Length);
    }

    [Fact]
    public void ConstructorThrowsArgumentException() {
        byte[] sbox = null;
        byte[] invSbox = new byte[256];
        Assert.Throws<ArgumentNullException>(() => 
            new RijndaelKeySchedule(0x1B, ref sbox, ref invSbox));
        sbox = new byte[128];
        invSbox = new byte[256];
        Assert.Throws<ArgumentException>(() => 
            new RijndaelKeySchedule(0x1B, ref sbox, ref invSbox));
    }

    [Theory]
    [InlineData(128, 4)]
    [InlineData(192, 6)]
    [InlineData(256, 8)]
    public void GenerateRoundKeysWrongKeyLengthThrowsArgumentException(int keySize, ushort Nk) {
        var (sbox, invSbox) = CreateSboxes();
        var keySchedule = new RijndaelKeySchedule(0x1B, ref sbox, ref invSbox, Nk, 4);
        Assert.Throws<ArgumentException>(() => keySchedule.GenerateRoundKeys(new byte[Nk * 4 - 1]));
    }

    [Theory]
    [InlineData(128, 4)]
    [InlineData(192, 6)]
    [InlineData(256, 8)]
    public void GenerateRoundKeysValidKeyReturns(int keySize, ushort Nk) {
        var (sbox, invSbox) = CreateSboxes();
        byte[] key = new byte[Nk * 4];
        new Random(42).NextBytes(key);
        var keySchedule = new RijndaelKeySchedule(0x1B, ref sbox, ref invSbox, Nk, 4);
        var roundKeys = keySchedule.GenerateRoundKeys(key);
        // The first key is equal to the initial one.
        Assert.Contains(roundKeys[0], key);

        Assert.NotNull(roundKeys);
        Assert.NotEmpty(roundKeys);

        var seen = new HashSet<string>();
        foreach (var roundKey in roundKeys) {
            // all keys are not null
            Assert.Equal(16, roundKey.Length);
            // all keys are different
            var keyStr = Convert.ToBase64String(roundKey);
            Assert.DoesNotContain(keyStr, seen);
            seen.Add(keyStr);
        }
    }

    private static (byte[] sbox, byte[] invSbox) CreateSboxes(byte mod = 0x1B) {
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
    public static IEnumerable<object[]> TestKey128Data() {
        byte[] key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        byte[] roundKey0 = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        byte[] roundKey1 = [
            0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1,
            0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05
        ];
        yield return new object[] { 4, key, 0, roundKey0 };
        yield return new object[] { 4, key, 1, roundKey1 };
    }
    public static IEnumerable<object[]> TestKey192Data() {
        byte[] key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
        ];
        byte[] roundKey0 = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        ];
        byte[] roundKey1 = [
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
            0xfe, 0x0c, 0x91, 0xf7, 0x24, 0x02, 0xf5, 0xa5
        ];
        yield return new object[] { 6, key, 0, roundKey0 };
        yield return new object[] { 6, key, 1, roundKey1 };
    }
    public static IEnumerable<object[]> TestKey256Data() {
        byte[] key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
        ];
        byte[] roundKey0 = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        ];
        yield return new object[] { 8, key, 0, roundKey0 };
    }
}
}
