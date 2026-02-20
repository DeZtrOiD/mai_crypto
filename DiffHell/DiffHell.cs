
using System.Numerics;
using System.Security.Cryptography;

public sealed class DiffieHellmanProtocol {
    private readonly BigInteger p;
    private readonly BigInteger g;
    private readonly BigInteger _privateKey;
    private readonly BigInteger _publicKey;

    public DiffieHellmanProtocol(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;

        var maxBytes = (p.GetBitLength() + 7) / 8;
        byte[] randomBytes = new byte[maxBytes];
        RandomNumberGenerator.Fill(randomBytes);
        var randomValue = new BigInteger(randomBytes, isUnsigned: true, isBigEndian: false);
        _privateKey = (randomValue % (p - 1)) + 1;
        _publicKey = BigInteger.ModPow(g, _privateKey, p);
    }


    public BigInteger GetPublicKey() => _publicKey;


    public BigInteger GetP() => p;


    public BigInteger GetG() => g;


    public BigInteger ComputeSharedSecret(BigInteger otherPublicKey) {
        return BigInteger.ModPow(otherPublicKey, _privateKey, p);
    }


    public byte[] DeriveSymmetricKey(BigInteger otherPublicKey) {
        BigInteger sharedSecret = ComputeSharedSecret(otherPublicKey);
        byte[] secretBytes = sharedSecret.ToByteArray(isUnsigned: false, isBigEndian: false);
        return SHA256.HashData(secretBytes);
    }

    public byte[] Encrypt(byte[] plaintext, BigInteger otherPublicKey) {
        byte[] key = DeriveSymmetricKey(otherPublicKey);
        byte[] ciphertext = (byte[])plaintext.Clone();
        var rc4 = new RC4(key);
        rc4.ProcessChunk(ciphertext, ciphertext.Length);
        return ciphertext;
    }


    public byte[] Decrypt(byte[] ciphertext, BigInteger otherPublicKey) {
        return Encrypt(ciphertext, otherPublicKey);
    }
}