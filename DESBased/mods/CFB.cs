
using DESBased.Core.Interfaces;
using DESBased.Core.Utils;

namespace DESBased.Core.Modes {
public class CFBMode : ICipherMode {
    private byte[]? _iv;
    private IBlockCipher? _cipher;

    public bool RequiresPadding => true;
    public bool RequiresIV => true;

    public void Init(IBlockCipher cipher, in byte[]? iv, params object[] args) {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        _cipher = cipher;
        if (iv is null) throw new ArgumentNullException("IV not initialized.");
        if (iv.Length != _cipher.BlockSize) throw new ArgumentException($"IV must be exactly {_cipher.BlockSize}.");
        _iv = (byte[])iv.Clone();
    }

    public byte[] Encrypt(in byte[] plaintext) {
        ValidateInput(_cipher, plaintext, _iv);

        byte[][] blocks = ByteUtils.Split(plaintext, _cipher!.BlockSize);
        byte[][] result = new byte[blocks.Length][];

        byte[] prev = (byte[])_iv!.Clone();

        for (int i = 0; i < blocks.Length; i++) {
            result[i] = ByteUtils.Xor(blocks[i], _cipher.Encrypt(prev));
            prev = result[i];
        }
        return ByteUtils.Concat(result);
    }

    public byte[] Decrypt(in byte[] ciphertext) {
        ValidateInput(_cipher, ciphertext, _iv);

        var blocks = ByteUtils.Split(ciphertext, _cipher!.BlockSize);
        var result = new byte[blocks.Length][];

        byte[] prev = (byte[])_iv!.Clone();

        for (int i = 0; i < blocks.Length; i++) {
            result[i] = ByteUtils.Xor(blocks[i], _cipher.Encrypt(prev));
            prev = blocks[i];
        }
        return ByteUtils.Concat(result);
    }
    private static void ValidateInput(IBlockCipher? cipher, byte[]? data, byte[]? _iv) {
        if (cipher is null) throw new InvalidOperationException("Cipher not initialized.");
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (_iv is null) throw new InvalidOperationException("IV not initialized.");
        if (data.Length % cipher.BlockSize != 0)
            throw new ArgumentException(
                $"Data length must be multiple of block size ({ cipher.BlockSize } bytes).");
    }
}
}
