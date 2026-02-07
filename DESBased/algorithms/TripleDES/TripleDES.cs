
using DESBased.Core.Interfaces;
using DESBased.Core.Ciphers.DES;

/// TripleDES-EDE
namespace DESBased.Core.Ciphers.TripleDES {
public sealed class TripleDESCipher : IBlockCipher {
    private readonly DESCipher _des1 = new();
    private readonly DESCipher _des2 = new();
    private readonly DESCipher _des3 = new();

    bool _initialized = false;

    public int BlockSize => 8;

    public void Init(in byte[] key) {
        if ( key is null ) throw new ArgumentNullException("TripleDES key is null.");
        if (key.Length != 16 && key.Length != 24)
            throw new ArgumentException("TripleDES key must be 128 or 192 bits.");

        _des1.Init(key[..8]);
        _des2.Init(key[8..16]);
        _des3.Init(key.Length == 24 ? key[16..] : key[..8]);
        _initialized = true;
    }

    public byte[] Encrypt(in byte[] block) {
        ValidateState( block );
        return _des3.Encrypt(_des2.Decrypt(_des1.Encrypt( block )));
    }

    public byte[] Decrypt(in byte[] block) {
        ValidateState( block );
        return _des1.Decrypt(_des2.Encrypt(_des3.Decrypt( block )));
    }

    private void ValidateState(in byte[] block) {
        if (!_initialized) throw new InvalidOperationException("Cipher not initialized. Call Init() first.");
        if ( block is null ) throw new ArgumentNullException("Block cannot be null.");
        if ( block.Length != BlockSize )
            throw new ArgumentException($"Block size must be exactly { BlockSize } bytes, but was { block.Length }.");
    }
}
}
