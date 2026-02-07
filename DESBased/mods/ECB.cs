
using DESBased.Core.Interfaces;
using DESBased.Core.Utils;

namespace DESBased.Core.Modes {
public class ECBMode : ICipherMode {
    public bool RequiresPadding => true;
    public bool RequiresIV => false;

    private IBlockCipher? _cipher;

    public void Init(IBlockCipher cipher, in byte[]? iv, params object[] args) {
        if (cipher is null)
            throw new ArgumentNullException("Cipher mode requer initialized cipher.");
        _cipher = cipher;
    }

    public byte[] Encrypt(in byte[] plaintext) {
        ValidateInput(_cipher, plaintext);
        byte[][] blocks = ByteUtils.Split(plaintext, _cipher!.BlockSize);
        
        Parallel.For(0, blocks.Length, i => blocks[i] = _cipher.Encrypt(blocks[i]));

        return ByteUtils.Concat(blocks);
    }

    public byte[] Decrypt(in byte[] ciphertext) {
        ValidateInput(_cipher, ciphertext);
        byte[][] blocks = ByteUtils.Split(ciphertext, _cipher!.BlockSize);
        
        Parallel.For(0, blocks.Length, i => blocks[i] = _cipher.Decrypt(blocks[i]));
        
        return ByteUtils.Concat(blocks);
    }

    private static void ValidateInput(IBlockCipher? cipher, byte[]? data) {
        if ( cipher is null ) throw new InvalidOperationException("Cipher not initialized.");
        if ( data is null ) throw new ArgumentNullException(nameof(data));
        if (data.Length % cipher.BlockSize != 0)
            throw new ArgumentException(
                $"Data length must be multiple of block size ({ cipher.BlockSize } bytes)."
        );
    }
}
}
