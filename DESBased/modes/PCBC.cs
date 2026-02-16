
using DESBased.Core.Interfaces;
using DESBased.Core.Utils;

namespace DESBased.Core.Modes {
public class PCBCMode : ICipherMode {
    private byte[]? _iv;
    private IBlockCipher? _cipher;
    public bool RequiresPadding => true;
    public bool RequiresIV => true;
    public void Init(IBlockCipher cipher, in byte[]? iv, params object[] args) {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        _cipher = cipher;

        if ( iv is null ) throw new ArgumentNullException("IV not initialized.");
        if (iv.Length != _cipher.BlockSize)
            throw new ArgumentException($"IV must be exactly {_cipher.BlockSize} bytes for CBC mode.");
        _iv = (byte[])iv.Clone();
    }

    public byte[] Encrypt(in byte[] plaintext) => Process(plaintext, true);
    public byte[] Decrypt(in byte[] ciphertext) => Process(ciphertext, false);

    private byte[] Process(in byte[] input, bool encrypt) {
        ValidateInput(_cipher, input, _iv);

        byte[][] blocks = ByteUtils.Split(input, _cipher!.BlockSize);
        byte[][] result = new byte[blocks.Length][];

        byte[] prevPlain = (byte[])_iv!.Clone();
        byte[] prevCipher = new byte[_iv.Length];

        for (int i = 0; i < blocks.Length; i++) {
            byte[] prev = ByteUtils.Xor(prevPlain, prevCipher);
            if (encrypt) {
                byte[] mixed = ByteUtils.Xor(blocks[i], prev);
                result[i] = _cipher.Encrypt(mixed);
                prevPlain = blocks[i];
                prevCipher = result[i];
            } else {
                var decrypted = _cipher.Decrypt(blocks[i]);
                result[i] = ByteUtils.Xor(decrypted, prev);
                prevPlain = result[i];
                prevCipher = blocks[i]; 
            }
        }
        return ByteUtils.Concat(result);
    }

    private static void ValidateInput(IBlockCipher? cipher, byte[]? data, byte[]? _iv) {
        if (cipher is null) throw new InvalidOperationException("Cipher not initialized.");
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (_iv is null) throw new InvalidOperationException("IV not initialized.");
        if (data.Length % cipher.BlockSize != 0)
            throw new ArgumentException(
                $"Data length must be multiple of block size ({cipher.BlockSize} bytes).");
    }
}
}
