
using DESBased.Core.Interfaces;
using DESBased.Core.Utils;

namespace DESBased.Core.Modes {
public class RandomDeltaMode : ICipherMode {
    private int? _seed;
    private IBlockCipher? _cipher;
    private byte[]? _iv;
    private byte[]? _delta;
    private bool _firstOp = true;
    private long _ksOffset;  // keyStreamOffset
    public bool RequiresPadding => false;
    public bool RequiresIV => true;
    public void Init(IBlockCipher cipher, in byte[]? iv, params object[] args) {
        if ((args is not null) && (args.Length > 0) && (args[0] is int seed)) _seed = seed;
        else _seed = null;

        if ( cipher is null ) throw new ArgumentNullException(nameof(cipher));
        _cipher = cipher;

        if ( iv is null ) throw new ArgumentNullException("IV not initialized.");
        if (iv.Length != _cipher.BlockSize)
            throw new ArgumentException($"IV must be exactly {_cipher.BlockSize} bytes for CBC mode.");
        _iv = (byte[])iv.Clone();

        _delta = null;
        _ksOffset = 0;
        _firstOp = true;
    }

    public byte[] Encrypt(in byte[] input) {
        ValidateInput(_cipher, input, _iv);
        EnsureDelta();
        if (input.Length == 0) return Array.Empty<byte>();

        var parts = new List<byte[]>();
        if ( _firstOp ) {
            parts.Add(_cipher!.Encrypt(_delta!));
            _firstOp = false;
        }

        byte[] body = ProcessBody(input);
        parts.Add(body);
        return ByteUtils.Concat(parts.ToArray());
    }

    public byte[] Decrypt(in byte[] input) {
        ValidateInput(_cipher, input, _iv);
        if (input.Length == 0) return Array.Empty<byte>();

        int bs = _cipher!.BlockSize;

        if ( _firstOp ) {
            if (input.Length < bs) throw new ArgumentException("Ciphertext too short: missing encrypted delta.");

            byte[] encryptedDelta = new byte[bs];
            Buffer.BlockCopy(input, 0, encryptedDelta, 0, bs);
            _delta = _cipher.Decrypt(encryptedDelta);
            _firstOp = false;

            if (input.Length == bs) return Array.Empty<byte>();

            byte[] remaining = new byte[input.Length - bs];
            Buffer.BlockCopy(input, bs, remaining, 0, remaining.Length);
            return ProcessBody(remaining);
        } else return ProcessBody(input);
    }

    private byte[] ProcessBody(in byte[] input) {
        if ( _delta is null ) throw new InvalidOperationException("Delta not initialized.");

        int bs = _cipher!.BlockSize;
        byte[] output = new byte[input.Length];

        int blocksNeeded = (int)(_ksOffset % bs + input.Length + bs - 1) / bs; // ceil(mes.length + key_offset)

        // _ksOffset == 0 -> point to unused block
        // _ksOffset > 0 -> points to partially used keystream block
        long firstBlockIndex = _ksOffset / bs;

        var keystreamSlice = new byte[blocksNeeded][];
        // counter = iv + delta * (firstBlockIndex + i)
        Parallel.For(0, blocksNeeded, i => {
            byte[] step = ByteUtils.MultiplyMod2N(_delta, (uint)(firstBlockIndex + i));
            keystreamSlice[i] = _cipher!.Encrypt(ByteUtils.AddMod2N(_iv!, step));
        });

        for (int i = 0; i < input.Length; i++) {
            long blockIdx = (_ksOffset % bs + i) / bs;
            long byteIdx = (_ksOffset % bs + i) % bs;
            output[i] = (byte)(input[i] ^ keystreamSlice[blockIdx][byteIdx]);
        }
        _ksOffset += input.Length;
        return output;
    }

    private void EnsureDelta() {
        if (_delta is not null) return;
        if (_cipher is null) throw new InvalidOperationException();

        int bs = _cipher.BlockSize;
        if (_seed.HasValue) {
            var d = new byte[bs];
            new Random(_seed.Value).NextBytes(d);
            _delta = d;
        } else {
            var d = new byte[bs];
            if (_iv is null) throw new InvalidOperationException("IV required for delta extraction.");
            Buffer.BlockCopy(_iv, 0, d, 0, bs / 2);
            _delta = d;
        }
    }

    private static void ValidateInput(IBlockCipher? cipher, byte[]? data, byte[]? _iv) {
        if (cipher is null) throw new InvalidOperationException("Cipher not initialized.");
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (_iv is null) throw new InvalidOperationException("IV not initialized.");
    }
}
}
