using System;
using System.Numerics;
using System.Text;
using Xunit;

namespace Cryptography.Block.DiffHell.Tests;

public class DiffieHellmanProtocolTests
{
    private static readonly BigInteger TestP = BigInteger.Parse("1797693134862315907708391567937874531978602960487560117064444236841971802183714537601907599972598351903311521872447167767833124872627905277935710151693349903928939575251211431962967789991617508552039973627980443584667464877438453835865191495461984923101491793986829085661083277834403310374200486169473840585283");
    private static readonly BigInteger TestG = BigInteger.Parse("2");


    [Fact]
    public void Constructor_GeneratesValidPrivateKeyInRange() {
        var dh = new DiffieHellmanProtocol(TestP, TestG);
        var privKey = GetPrivateKey(dh);
        Assert.True(privKey >= 1 && privKey < TestP);
    }


    [Fact]
    public void Constructor_GeneratesConsistentPublicKey() {
        var dh = new DiffieHellmanProtocol(TestP, TestG);
        var pubKey = dh.GetPublicKey();
        var expected = BigInteger.ModPow(TestG, GetPrivateKey(dh), TestP);
        Assert.Equal(expected, pubKey);
    }


    [Fact]
    public void ComputeSharedSecret_IsSymmetric() {
        var alice = new DiffieHellmanProtocol(TestP, TestG);
        var bob = new DiffieHellmanProtocol(TestP, TestG);

        var secretA = alice.ComputeSharedSecret(bob.GetPublicKey());
        var secretB = bob.ComputeSharedSecret(alice.GetPublicKey());

        Assert.Equal(secretA, secretB);
    }


    [Fact]
    public void DeriveSymmetricKey_ProducesSameKeyForBothParties() {
        var alice = new DiffieHellmanProtocol(TestP, TestG);
        var bob = new DiffieHellmanProtocol(TestP, TestG);

        var keyA = alice.DeriveSymmetricKey(bob.GetPublicKey());
        var keyB = bob.DeriveSymmetricKey(alice.GetPublicKey());

        Assert.Equal(keyA, keyB);
    }


    [Fact]
    public void DeriveSymmetricKey_OutputIs32Bytes() {
        var alice = new DiffieHellmanProtocol(TestP, TestG);
        var bob = new DiffieHellmanProtocol(TestP, TestG);

        var key = alice.DeriveSymmetricKey(bob.GetPublicKey());
        Assert.Equal(32, key.Length);
    }


    [Fact]
    public void EncryptDecrypt_RoundTrip_Success() {
        var alice = new DiffieHellmanProtocol(TestP, TestG);
        var bob = new DiffieHellmanProtocol(TestP, TestG);

        string original = "Secret message for testing!";
        byte[] plaintext = Encoding.UTF8.GetBytes(original);

        byte[] ciphertext = alice.Encrypt(plaintext, bob.GetPublicKey());
        byte[] decrypted = bob.Decrypt(ciphertext, alice.GetPublicKey());

        string result = Encoding.UTF8.GetString(decrypted);
        Assert.Equal(original, result);
    }


    [Fact]
    public void EncryptDecrypt_WithEmptyMessage() {
        var alice = new DiffieHellmanProtocol(TestP, TestG);
        var bob = new DiffieHellmanProtocol(TestP, TestG);

        byte[] plaintext = Array.Empty<byte>();
        byte[] ciphertext = alice.Encrypt(plaintext, bob.GetPublicKey());
        byte[] decrypted = bob.Decrypt(ciphertext, alice.GetPublicKey());

        Assert.Empty(decrypted);
    }


    [Fact]
    public void EncryptDecrypt_WithSingleByteMessage() {
        var alice = new DiffieHellmanProtocol(TestP, TestG);
        var bob = new DiffieHellmanProtocol(TestP, TestG);

        byte[] plaintext = { 0x42 };
        byte[] ciphertext = alice.Encrypt(plaintext, bob.GetPublicKey());
        byte[] decrypted = bob.Decrypt(ciphertext, alice.GetPublicKey());

        Assert.Equal(plaintext, decrypted);
    }


    [Fact]
    public void Getters_ReturnCorrectValues() {
        var dh = new DiffieHellmanProtocol(TestP, TestG);
        Assert.Equal(TestP, dh.GetP());
        Assert.Equal(TestG, dh.GetG());
        Assert.True(dh.GetPublicKey() > 0);
    }


    [Fact]
    public void DifferentInstances_HaveDifferentKeys() {
        var dh1 = new DiffieHellmanProtocol(TestP, TestG);
        var dh2 = new DiffieHellmanProtocol(TestP, TestG);

        Assert.NotEqual(dh1.GetPublicKey(), dh2.GetPublicKey());
        Assert.NotEqual(GetPrivateKey(dh1), GetPrivateKey(dh2));
    }


    private static BigInteger GetPrivateKey(DiffieHellmanProtocol instance) {
        var field = typeof(DiffieHellmanProtocol).GetField("_privateKey", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        return (BigInteger)field.GetValue(instance);
    }
}