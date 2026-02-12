
namespace Rijndael.Tests {
public class RijndaelBlockCipherTests {
    [Theory]
    [MemberData(nameof(ValidBlockKeySizes))]
    public void ConstructorValidParametersCreatesInstance(ushort blockSize, ushort keySize) {
        var cipher = new RijndaelBlockCipher(blockSize, keySize, 0x1B);
        Assert.NotNull(cipher);
        Assert.Equal(blockSize / 8, cipher.BlockSize);
    }

    [Theory]
    [MemberData(nameof(InvalidBlockSizes))]
    public void ConstructorInvalidBlockSizeThrowsArgumentException(ushort invalidBlockSize) => 
        Assert.Throws<ArgumentException>(() => new RijndaelBlockCipher(invalidBlockSize, 128, 0x1B));

    [Theory]
    [MemberData(nameof(InvalidKeySizes))]
    public void ConstructorInvalidKeySizeThrowsArgumentException(ushort invalidKeySize) =>
        Assert.Throws<ArgumentException>(() => new RijndaelBlockCipher(128, invalidKeySize, 0x1B));

    [Theory]
    [InlineData(0x11)]
    [InlineData(0x03)]
    public void ConstructorReducibleModulusThrowsArgumentException(byte reducibleMod) =>
        Assert.Throws<ArgumentException>(() => new RijndaelBlockCipher(128, 128, reducibleMod));

    [Theory]
    [MemberData(nameof(IrreduciblePolynomials))]
    public void ConstructorDifferentIrreducibleModuliCreateValidInstances(byte gfMod) {
        var cipher = new RijndaelBlockCipher(128, 128, gfMod);
        Assert.NotNull(cipher);
        var key = new byte[16];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
        cipher.Init(key);
        var plaintext = new byte[16];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(plaintext);
        Assert.Equal(plaintext, cipher.Decrypt(cipher.Encrypt(plaintext)));
    }

    [Theory]
    [MemberData(nameof(ValidBlockKeySizes))]
    public void InitValidKeyDoesNotThrow(ushort blockSize, ushort keySize) {
        var key = new byte[keySize / 8];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
        new RijndaelBlockCipher(blockSize, keySize, 0x1B).Init(key);
    }

    [Theory]
    [MemberData(nameof(ValidBlockKeySizes))]
    public void InitInvalidKeyLengthThrowsArgumentException(ushort blockSize, ushort keySize) =>
        Assert.Throws<ArgumentException>(() => new RijndaelBlockCipher(blockSize, keySize, 0x1B)
            .Init(new byte[keySize / 8 + 1]));

    [Fact]
    public void InitTwiceWithDifferentKeysChangesRoundKeys() {
        var cipher = new RijndaelBlockCipher(128, 128, 0x1B);
        var key1 = new byte[16]; key1[0] = 0x01;
        var key2 = new byte[16]; key2[0] = 0x02;
        var block = new byte[16]; block[0] = 0xAA;
        cipher.Init(key1);
        byte[] cipherText = cipher.Encrypt(block);
        cipher.Init(key2);
        Assert.NotEqual(cipherText, cipher.Encrypt(block));
    }

    [Theory]
    [MemberData(nameof(ValidBlockKeySizes))]
    public void EncryptDecryptRoundTripReturnsOriginal(ushort blockSize, ushort keySize) {
        var cipher = new RijndaelBlockCipher(blockSize, keySize, 0x1B);
        var key = new byte[keySize / 8];
        var plaintext = new byte[blockSize / 8];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(plaintext);
        cipher.Init(key);
        Assert.Equal(plaintext, cipher.Decrypt(cipher.Encrypt(plaintext)));
    }

    [Theory]
    [InlineData(true)]  // Encrypt without Init
    [InlineData(false)]  // Decrypt without Init
    public void OperationWithoutInitThrowsInvalidOperationException(bool isEncrypt) {
        var cipher = new RijndaelBlockCipher(128, 128, 0x1B);
        var block = new byte[16];
        if (isEncrypt) Assert.Throws<InvalidOperationException>(() => cipher.Encrypt(block));
        else Assert.Throws<InvalidOperationException>(() => cipher.Decrypt(block));
    }

    [Theory]
    [InlineData(128, 128, 15, true)]  // Encrypt wrong size
    [InlineData(128, 128, 15, false)]  // Decrypt wrong size
    [InlineData(192, 192, 23, true)]
    [InlineData(192, 192, 23, false)]
    [InlineData(256, 256, 31, true)]
    [InlineData(256, 256, 31, false)]
    public void OperationWrongBlockSizeThrowsArgumentException(
        int blockSize, int keySize, int wrongLength, bool isEncrypt
    ) {
        var cipher = new RijndaelBlockCipher((ushort)blockSize, (ushort)keySize, 0x1B);
        var key = new byte[keySize / 8];
        cipher.Init(key);
        if (isEncrypt) Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[wrongLength]));
        else Assert.Throws<ArgumentException>(() => cipher.Decrypt(new byte[wrongLength]));
    }

    [Theory]
    [MemberData(nameof(AesTestVectors))]
    public void EncryptAesKnownVectorsProducesCorrectCiphertext(
        int blockSize, int keySize, byte[] key, byte[] plaintext, byte[] expectedCiphertext
    ) {
        var cipher = new RijndaelBlockCipher((ushort)blockSize, (ushort)keySize, 0x1B);
        cipher.Init(key);
        Assert.Equal(expectedCiphertext, cipher.Encrypt(plaintext));
        Assert.Equal(plaintext, cipher.Decrypt(expectedCiphertext));
    }

    [Theory]
    [MemberData(nameof(ValidBlockKeySizes))]
    public void DifferentInputsOrKeysProduceDifferentCiphertexts(ushort blockSize, ushort keySize) {
        var cipher = new RijndaelBlockCipher(blockSize, keySize, 0x1B);
        int byteSize = keySize / 8;
        int blockSizeBytes = blockSize / 8;
        {  // Different keys -> different ciphertexts
            var key1 = new byte[byteSize]; new Random(42).NextBytes(key1);
            var key2 = new byte[byteSize]; new Random(43).NextBytes(key2);
            var plaintext = new byte[blockSizeBytes]; new Random(Guid.NewGuid().GetHashCode()).NextBytes(plaintext);
            cipher.Init(key1);
            var ct1 = cipher.Encrypt(plaintext);
            cipher.Init(key2);
            Assert.NotEqual(ct1, cipher.Encrypt(plaintext));
        } { // Different texts -> different ciphertexts
            var key = new byte[byteSize]; new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
            var plaintext1 = new byte[blockSizeBytes]; new Random(46).NextBytes(plaintext1);
            var plaintext2 = new byte[blockSizeBytes]; new Random(47).NextBytes(plaintext2);
            cipher.Init(key);
            Assert.NotEqual(cipher.Encrypt(plaintext1), cipher.Encrypt(plaintext2));
        }
    }

    [Theory]
    [MemberData(nameof(ValidBlockKeySizes))]
    public void EncryptDeterministicSameInputSameOutput(ushort blockSize, ushort keySize) {
        var cipher = new RijndaelBlockCipher(blockSize, keySize, 0x1B);
        var key = new byte[keySize / 8];
        var plaintext = new byte[blockSize / 8];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(plaintext);
        cipher.Init(key);
        Assert.Equal(cipher.Encrypt(plaintext), cipher.Encrypt(plaintext));
    }

    [Theory]
    [MemberData(nameof(IrreduciblePolynomials))]
    public void RoundTripWithDifferentIrreducibleModuliReturnsOriginal(byte gfMod) {
        var cipher = new RijndaelBlockCipher(128, 128, gfMod);
        var key = new byte[16];
        var plaintext = new byte[16];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(plaintext);
        cipher.Init(key);
        var ciphertext = cipher.Encrypt(plaintext);
        Assert.NotEqual(plaintext, ciphertext);
        Assert.Equal(plaintext, cipher.Decrypt(ciphertext));
    }

    [Theory]
    [MemberData(nameof(IrreduciblePolynomialPairs))]
    public void DifferentModuliProduceDifferentCiphertexts(byte gfMod1, byte gfMod2) {
        if (gfMod1 == gfMod2) return;
        var key = new byte[16];
        var plaintext = new byte[16];
        new Random(42).NextBytes(key);
        new Random(43).NextBytes(plaintext);
        var cipher1 = new RijndaelBlockCipher(128, 128, gfMod1);
        cipher1.Init(key);
        var cipher2 = new RijndaelBlockCipher(128, 128, gfMod2);
        cipher2.Init(key);
        Assert.NotEqual(cipher1.Encrypt(plaintext), cipher2.Encrypt(plaintext));
    }

    public static IEnumerable<object[]> AesTestVectors() {
        yield return new object[] {
            128, 128, (byte[])[
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
            ], (byte[])[
                0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
            ], (byte[])[
                0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
            ],
        };
        yield return new object[] {
            128, 128, (byte[])[
                0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59,
                0x1c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98
            ], (byte[])[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
            ], (byte[])[
                0x34, 0xd3, 0xf0, 0xee, 0xcb, 0x4d, 0xfa, 0x16,
                0xcb, 0x8b, 0xf0, 0x7f, 0x29, 0xa0, 0xcb, 0x79
            ],
        };
    }

    public static IEnumerable<object[]> ValidBlockKeySizes() {
        foreach (var blockSize in new[] { 128, 192, 256 })
        foreach (var keySize in new[] { 128, 192, 256 })
            yield return new object[] { (ushort)blockSize, (ushort)keySize };
    }

    public static IEnumerable<object[]> InvalidBlockSizes() => (object[][])[[0], [64], [160], [512]];
    public static IEnumerable<object[]> InvalidKeySizes() => (object[][])[[0], [64], [160], [512]];
    public static IEnumerable<object[]> IrreduciblePolynomials() {
        yield return [(byte)0x1B];  // x^8 + x^4 + x^3 + x + 1
        yield return [(byte)0x1D];  // x^8 + x^4 + x^3 + x^2 + 1
        yield return [(byte)0x2B];  // x^8 + x^5 + x^3 + x + 1
        yield return [(byte)0x39];  // x^8 + x^5 + x^4 + x^3 + 1
        yield return [(byte)0x4D];  // x^8 + x^6 + x^3 + x^2 + 1
        yield return [(byte)0x63];  // x^8 + x^6 + x^5 + x + 1
        yield return [(byte)0x87];  // x^8 + x^7 + x^2 + x + 1
        yield return [(byte)0xA9];  // x^8 + x^7 + x^5 + x^3 + 1
        yield return [(byte)0xBD];  // x^8 + x^7 + x^5 + x^4 + x^3 + x^2 + 1
        yield return [(byte)0xCF];  // x^8 + x^7 + x^6 + x^3 + x^2 + x + 1
    }
    public static IEnumerable<object[]> IrreduciblePolynomialPairs() {
        var polys = IrreduciblePolynomials().SelectMany(x => x).ToList();
        for (int i = 0; i < polys.Count; i++)
        for (int j = 0; j < polys.Count; j++) if (i != j) yield return [polys[i], polys[j]];
    }
}
}
