
namespace DESBased.Core.Interfaces {
public interface IBlockCipher {
    int BlockSize { get; }
    void Init(in byte[] key);
    byte[] Encrypt(in byte[] block);
    byte[] Decrypt(in byte[] block);
}
}
