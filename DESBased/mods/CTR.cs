
using DESBased.Core.Interfaces;
using DESBased.Core.Utils;

namespace DESBased.Core.Modes {
public class CTRMode : ICipherMode {
    private byte[]? _iv;
    private long _ksOffset;
    private IBlockCipher? _cipher;
    public bool RequiresPadding => false;
    public bool RequiresIV => true;

    public void Init(IBlockCipher cipher, in byte[]? iv, params object[] args) {
        if (cipher == null) throw new ArgumentNullException(nameof(cipher));
        _cipher = cipher;
        if (iv is null) throw new ArgumentNullException("IV not initialized.");
        if (iv.Length != _cipher.BlockSize)
            throw new ArgumentException($"IV must be exactly {_cipher.BlockSize} bytes for CBC mode.");
        _iv = (byte[])iv.Clone();
        _ksOffset = 0;
    }

    public byte[] Encrypt(in byte[] plaintext) => Process(plaintext);
    public byte[] Decrypt(in byte[] ciphertext) => Process(ciphertext);

    private byte[] Process(in byte[] input) {
        ValidateInput(_cipher, input, _iv);

        ulong blockSize = (ulong)_cipher!.BlockSize;
        byte[] output = new byte[input.Length];

        ulong startByte = (ulong)_ksOffset;
        ulong endByte = startByte + (ulong)input.Length;

        ulong firstBlock = startByte / blockSize;
        ulong lastBlock  = (endByte - 1) / blockSize;
        int blockCount = (int)(lastBlock - firstBlock + 1);

        var keystream = new byte[blockCount][];

        Parallel.For(0, blockCount, i => {
            var counterBlock = (byte[])_iv!.Clone();
            ByteUtils.AddBigEndian2pow8(counterBlock, firstBlock + (ulong)i);
            keystream[i] = _cipher.Encrypt(counterBlock);
        });

        for (int i = 0; i < input.Length; i++) {
            ulong globalByte = startByte + (ulong)i;
            ulong blockIdx = globalByte / blockSize - firstBlock;
            ulong byteIdx  = globalByte % blockSize;
            output[i] = (byte)(input[i] ^ keystream[blockIdx][byteIdx]);
        }

        _ksOffset += input.Length;
        return output;
    }
    private static void ValidateInput(IBlockCipher? cipher, byte[]? data, byte[]? _iv) {
        if (cipher is null) throw new InvalidOperationException("Cipher not initialized.");
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (_iv is null) throw new InvalidOperationException("IV not initialized.");
    }
}
}
