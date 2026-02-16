
using DESBased.Core.Interfaces;

namespace DESBased.Core.Modes {
public class OFBMode : ICipherMode {
    private byte[]? _iv;
    private byte[]? _ksBlock;
    private long _ksOffset;
    private IBlockCipher? _cipher;

    public bool RequiresPadding => false;
    public bool RequiresIV => true;

    public void Init(IBlockCipher cipher, in byte[]? iv, params object[] args) {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        _cipher = cipher;
        if (iv is null) throw new ArgumentNullException("IV not initialized.");
        if (iv.Length != _cipher.BlockSize)
            throw new ArgumentException($"IV must be exactly { _cipher.BlockSize } bytes for CBC mode.");

        _iv = (byte[])iv.Clone();

        _ksBlock = null;
        _ksOffset = 0;
    }

    public byte[] Encrypt(in byte[] input) => Process(input);
    public byte[] Decrypt(in byte[] input) => Process(input);

    private byte[] Process(byte[] input) {
        ValidateInput(_cipher, input, _iv);
        int blockSize = _cipher!.BlockSize;
        byte[] output = new byte[input.Length];

        if (_ksBlock is null) {
            _ksBlock = _cipher.Encrypt(_iv!);
            _ksOffset = 0;
        }

        for (int i = 0; i < input.Length; i++) {
            if (_ksOffset == blockSize) {
                _ksBlock = _cipher.Encrypt(_ksBlock);
                _ksOffset = 0;
            }
            output[i] = (byte)(input[i] ^ _ksBlock[_ksOffset++]);
        }
        return output;
    }
    private static void ValidateInput(IBlockCipher? cipher, byte[]? data, byte[]? _iv) {
        if (cipher is null) throw new InvalidOperationException("Cipher not initialized.");
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (_iv is null) throw new InvalidOperationException("IV not initialized.");
    }
}
}
