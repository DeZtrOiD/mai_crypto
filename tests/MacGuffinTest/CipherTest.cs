
#pragma warning disable CS8625
#pragma warning disable xUnit1013

using MacGuffin.Schedule;

namespace MacGuffin.Tests {
public class MacGuffinCipherTests {
    [Theory]
    [InlineData(
        (byte[])[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        (byte[])[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])]
    [InlineData(
        (byte[])[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        (byte[])[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])]
    [InlineData(
        (byte[])[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10],
        (byte[])[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])]
    public void EncryptDecryptRoundTripSuccess(byte[] key, byte[] plaintext) {
        var cipher = new MacGuffinCipher();
        cipher.Init(key);
        var ciphertext = cipher.Encrypt(plaintext);
        Assert.Equal(plaintext, cipher.Decrypt(ciphertext));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    public void InitInvalidKeyLengthThrowsException(int len) =>
        Assert.Throws<ArgumentException>(() => new MacGuffinCipher().Init(new byte[len]));

    public void InitNulllKeyThrowsException() =>
        Assert.Throws<ArgumentNullException>(() => new MacGuffinCipher().Init(null));

    [Fact]
    public void EncryptDecryptWithoutInitThrowsException() {
        var cipher = new MacGuffinCipher();
        var block = new byte[8];
        Assert.Throws<InvalidOperationException>(() => cipher.Encrypt(block));
        Assert.Throws<InvalidOperationException>(() => cipher.Decrypt(block));
    }

    [Theory]
    [InlineData(7)]
    [InlineData(9)]
    public void EncryptDecryptInvalidBlockSizeThrowsException(int len) {
        var cipher = new MacGuffinCipher();
        var key = new byte[16];
        cipher.Init(key);
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[len]));
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(new byte[len]));
    }

    public void EncryptDecryptNullBlockThrowsException(int len) {
        var cipher = new MacGuffinCipher();
        var key = new byte[16];
        cipher.Init(key);
        Assert.Throws<ArgumentNullException>(() => cipher.Encrypt(null));
        Assert.Throws<ArgumentNullException>(() => cipher.Decrypt(null));
    }

    public void DifferentKeysProduceDifferentCiphertexts() {
        var key1 = new byte[16];
        var key2 = new byte[16];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key1);
        var plaintext = new byte[8];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(plaintext);
        key2 = key1;
        key2[0] ^= 1;

        var cipher1 = new MacGuffinCipher();
        cipher1.Init(key1);
        var ciphertext1 = cipher1.Encrypt(plaintext);
        var cipher2 = new MacGuffinCipher();
        cipher2.Init(key2);
        
        Assert.NotEqual(ciphertext1, cipher2.Encrypt(plaintext));
        cipher1.Init(key2);
        Assert.NotEqual(ciphertext1, cipher1.Encrypt(plaintext));
    }

    [Fact]
    public void MultipleEncryptionsSameResult() {
        var cipher = new MacGuffinCipher();
        var key = new byte[16];
        var plaintext = new byte[8];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(plaintext);

        cipher.Init(key);
        var ciphertext1 = cipher.Encrypt(plaintext);
        var ciphertext2 = cipher.Encrypt(plaintext);

        Assert.Equal(ciphertext1, ciphertext2);
    }


    [Fact]
    public void KeyScheduleGeneratesCorrectNumberOfKeys() {
        var keySchedule = new MacGuffinKeySchedule();
        var key = new byte[16];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
        var roundKeys = keySchedule.GenerateRoundKeys(key);
        
        Assert.Equal(96, roundKeys.Length);
    }
}
}
