
#pragma warning disable CS8625
#pragma warning disable xUnit1026

namespace DESBased.Core.Ciphers.DEAL.Tests {
public class DealCipherTests {

    [Theory]
    [MemberData(nameof(GetSettings))]
    public void DEALWalidData(int keySizeBits, int rounds) {
        var cipher = new DEALCipher(keySizeBits);
        Assert.NotNull(cipher);

        cipher.Init(GenerateDealKey(keySizeBits));
        byte[] block = new byte[16];
        var random = new Random(Guid.NewGuid().GetHashCode());

        for (int i = 0; i < 100; i++) {
            random.NextBytes(block);
            var encrypted = cipher.Encrypt(block);
            Assert.NotEqual(block, encrypted);
            Assert.Equal(block, cipher.Decrypt(encrypted));
        }
    }

    [Theory]
    [MemberData(nameof(GetSettings))]
    public void DEALKeyDependency(int keySizeBits, int rounds) {
        var cipher1 = new DEALCipher(keySizeBits);
        var cipher2 = new DEALCipher(keySizeBits);
        var cipher3 = new DEALCipher(keySizeBits);
        byte[] block = new byte[16];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(block);

        byte[] key1 = GenerateDealKey(keySizeBits, new Random(Guid.NewGuid().GetHashCode()));
        byte[] key2 = (byte[])key1.Clone();
        key2[0] ^= 0x12;
        block = [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 ];
        
        cipher1.Init(key1);
        cipher2.Init(key2);
        cipher3.Init(key1);

        Assert.NotEqual(key1, key2);
        
        var enc1 = cipher1.Encrypt(block);
        var enc2 = cipher2.Encrypt(block);
        
        Assert.NotEqual(enc1, enc2);
        Assert.Equal(cipher1.Decrypt(enc1), cipher2.Decrypt(enc2));
        Assert.Equal(
            cipher1.Decrypt(cipher1.Encrypt(block)),
            cipher3.Decrypt(cipher3.Encrypt(block))
        );

        Assert.Equal(rounds, new DEALKeySchedule(keySizeBits).GenerateRoundKeys(GenerateDealKey(keySizeBits)).Length); 
    }

    [Theory]
    [InlineData(0)]
    [InlineData(64)]
    [InlineData(130)]
    [InlineData(512)]
    public void InvalidKeySizeShouldThrow(int invalidKeySize) {
        Assert.Throws<ArgumentException>(() => new DEALCipher(invalidKeySize));
    }

    [Fact]
    public void EncryptDecryptNotInitializedShouldThrow() {
        var cipher = new DEALCipher(128);
        Assert.Throws<InvalidOperationException>(() => cipher.Encrypt(new byte[16]));
        Assert.Throws<InvalidOperationException>(() => cipher.Decrypt(new byte[16]));
    }

    [Theory]
    [MemberData(nameof(GetBadData))]
    public void EncryptDecryptInvalidBlockSizeShouldThrow(int size, byte[] data) {
        var cipher = new DEALCipher(size);
        cipher.Init(GenerateDealKey(size));
        if (data is null) {
            Assert.Throws<ArgumentNullException>(() => new DEALCipher(size).Init(null!));
            Assert.Throws<ArgumentNullException>(() => cipher.Encrypt(null));
            Assert.Throws<ArgumentNullException>(() => cipher.Encrypt(null));
        } else {
            Assert.Throws<ArgumentException>(() => new DEALCipher(size).Init(data));
            Assert.Throws<ArgumentException>(() => cipher.Encrypt(data));
            Assert.Throws<ArgumentException>(() => cipher.Decrypt(data));
        }
    }

    public static IEnumerable<object[]> GetBadData() {
        yield return [256, null];
        yield return [256, new byte[15]];
        yield return [256, new byte[17]];
        yield return [256, new byte[0]];
        yield return [256, new byte[130]];
        yield return [256, new byte[270]];
        yield return [256, new byte[512]];

        yield return [192, null];
        yield return [192, new byte[15]];
        yield return [192, new byte[17]];
        yield return [192, new byte[0]];
        yield return [192, new byte[130]];
        yield return [192, new byte[270]];
        yield return [192, new byte[512]];

        yield return [128, null];
        yield return [128, new byte[15]];
        yield return [128, new byte[17]];
        yield return [128, new byte[0]];
        yield return [128, new byte[130]];
        yield return [128, new byte[270]];
        yield return [128, new byte[512]];
    }

    private static byte[] GenerateDealKey(int sizeBits, Random random = null) {
        if (sizeBits != 192 && sizeBits != 256 && sizeBits != 128) throw new ArgumentException();
        random ??= new Random(Guid.NewGuid().GetHashCode());
        byte[] key = new byte[sizeBits / 8];
        random.NextBytes(key);
        return key;
    }

    public static IEnumerable<object[]>GetSettings() {
        yield return [ 128, 6 ];
        yield return [ 192, 6 ];
        yield return [ 256, 8 ];
    }
}
}
