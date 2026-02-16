
namespace DESBased.Core.Interfaces {
public interface ICipherMode {
    void Init(IBlockCipher cipher, in byte[]? iv, params object[] args);
    byte[] Encrypt(in byte[] plaintext);
    byte[] Decrypt(in byte[] ciphertext);
    bool RequiresPadding { get; }
    bool RequiresIV { get; }
}
}