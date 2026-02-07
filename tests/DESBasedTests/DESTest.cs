
#pragma warning disable CS8625
#pragma warning disable CS8604
#pragma warning disable xUnit1026

namespace DESBased.Core.Ciphers.DES.Tests {
public class DesCipherTests {
    [Fact]
    public void KeyScheduleGenerateRoundKeysShouldProduce16Keys() {
        var keySchedule = new DESKeySchedule();
        byte[] key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        byte[][] roundKeys = keySchedule.GenerateRoundKeys(key);
        Assert.Equal(16, roundKeys.Length);
        foreach (var rk in roundKeys) Assert.Equal(6, rk.Length); // 48 бит = 6 байт
    }

    [Fact]
    public void KeyScheduleInvalidParityShouldThrow() {
        Assert.Throws<ArgumentException>(() => (new DESKeySchedule())  // Parity is violated.
            .GenerateRoundKeys([ 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xE1 ])
        );
    }

    [Theory]
    [MemberData(nameof(GetData))]
    public void EncryptShouldMatchExpected(byte[] key, byte[] plaintext, byte[] ciphertext) {
        var cipher = new DESCipher();
        cipher.Init(key);
        Assert.Equal(ciphertext, cipher.Encrypt(plaintext));
        Assert.Equal(plaintext, cipher.Decrypt(ciphertext));
        Assert.Equal(plaintext, cipher.Decrypt(cipher.Encrypt(plaintext)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData((byte[])[ 0, 0, 0, 0, 0, 0, 0 ])]
    [InlineData((byte[])[ 0, 0, 0, 0, 0, 0, 0, 0, 0 ])]
    [InlineData((byte[])[ 0 ])]
    [InlineData((byte[])[])]
    public void EncryptInvalidBlockSizeShouldThrow(byte[]? input) {
        var cipher = new DESCipher();
        cipher.Init([ 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 ]);
        if ( input is null ) {
            Assert.Throws<ArgumentNullException>(() => cipher.Encrypt(input));
            Assert.Throws<ArgumentNullException>(() => cipher.Decrypt(input));
            Assert.Throws<ArgumentNullException>(() => cipher.Init(input));
        } else {
            Assert.Throws<ArgumentException>(() => cipher.Encrypt(input));
            Assert.Throws<ArgumentException>(() => cipher.Decrypt(input));
            Assert.Throws<ArgumentException>(() => cipher.Init(input));
        }
    }

    public static IEnumerable<object[]> GetData() {
        // Key, plaintext, ciphertext
        yield return (byte[][])[
            [ 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 ],
            [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF ],
            [ 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 ]
        ];
        yield return (byte[][])[
            [ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 ],
            [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
            [ 0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00 ]
        ];
        yield return (byte[][])[
            [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF ],
            [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF ],
            [ 0x56, 0xCC, 0x09, 0xE7, 0xCF, 0xDC, 0x4C, 0xEF ]
        ];
        yield return (byte[][])[
            [ 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE ],
            [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF ],
            [ 0x6D, 0xCE, 0x0D, 0xC9, 0x00, 0x65, 0x56, 0xA3 ]
        ];
    }
}
}
