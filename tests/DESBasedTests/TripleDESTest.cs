
#pragma warning disable CS8625
#pragma warning disable CS8604
#pragma warning disable xUnit1026

namespace DESBased.Core.Ciphers.TripleDES.Tests {
public class TripleDesCipherTests {

    [Fact]
    public void RoundTripRandomDataShouldBeIdentity() {
        var cipher = new TripleDESCipher();
        var random = new Random(Guid.NewGuid().GetHashCode());
        byte[] block = new byte[8];

        foreach (int count in (int[])[16, 24]) {
            byte[] key = new byte[count];
            for (int i = 0; i < 100; i++) {
                random.NextBytes(key);
                random.NextBytes(block);
                cipher.Init(EnsureOddParity(key));
                Assert.Equal(block, cipher.Decrypt(cipher.Encrypt(block)));
            }
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(23)]
    [InlineData(25)]
    public void InitInvalidKeySizeShouldThrow(int keySize) {
        Assert.Throws<ArgumentException>(() => new TripleDESCipher().Init(new byte[keySize]));
    }

    [Fact]
    public void InitNullKeyShouldThrow() {
        Assert.Throws<ArgumentNullException>(() => new TripleDESCipher().Init(null));
    }

    [Fact]
    public void EncryptDecryptNotInitializedShouldThrow() {
        Assert.Throws<InvalidOperationException>(() => new TripleDESCipher().Encrypt(new byte[8]));
        Assert.Throws<InvalidOperationException>(() => new TripleDESCipher().Decrypt(new byte[8]));
    }

    [Theory]
    [InlineData(null)]
    [InlineData((byte[])[ 0, 0, 0, 0, 0, 0, 0])]
    [InlineData((byte[])[ 0, 0, 0, 0, 0, 0, 0, 0, 0])]
    [InlineData((byte[])[ ])]
    public void EncryptDecryptInvalidBlockSizeShouldThrow(byte[]? data) {
        var cipher = new TripleDESCipher();
        cipher.Init(EnsureOddParity(new byte[16]));
        if (data is null) {
            Assert.Throws<ArgumentNullException>(() => cipher.Encrypt(data));
            Assert.Throws<ArgumentNullException>(() => cipher.Decrypt(data));
        } else {
            Assert.Throws<ArgumentException>(() => cipher.Encrypt(data));
            Assert.Throws<ArgumentException>(() => cipher.Decrypt(data));       
        }
    }

    private static byte[] EnsureOddParity(byte[] keyPart) {
        if (keyPart.Length != 24 && keyPart.Length != 16) throw new ArgumentException();
        byte[] result = (byte[])keyPart.Clone();
        for (int i = 0; i < result.Length; i++) {
            bool parity = true;
            for (int j = 0; j < 8; j++) parity ^= (result[i] & (1 << (7 - j))) != 0;
            if (parity) result[i] ^= 0x01;
        }
        return result;
    }
}
}
