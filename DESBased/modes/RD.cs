
// #define RANDOM_DELTA_ALTERNATIVE_SUPER_VERSION

using DESBased.Core.Interfaces;
using DESBased.Core.Utils;

#if !RANDOM_DELTA_ALTERNATIVE_SUPER_VERSION

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

#else 

namespace DESBased.Core.Modes {
    public class RandomDeltaMode : ICipherMode {
        private const int _MIN_STEP = 1;
        private const int _MAX_STEP = 100;
        private IBlockCipher? _cipher;
        private byte[]? _nonce;
        private Random? _random;
        private long _counter;
        private byte[]? _currentKeystream;
        private int _offsetInBlock;
        public bool RequiresPadding => false;
        public bool RequiresIV => true;

        public void Init(IBlockCipher cipher, in byte[]? iv, params object[] args) {
            _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));

            if (iv is null) throw new ArgumentNullException(nameof(iv), "IV not initialized.");
            if (iv.Length != _cipher.BlockSize) throw new ArgumentException($"IV must be exactly {_cipher.BlockSize} bytes.");

            int nonceSize = _cipher.BlockSize / 2;
            _nonce = new byte[nonceSize];
            Buffer.BlockCopy(iv, 0, _nonce, 0, nonceSize);

            int? seed = null;
            int initialCounter = 0;

            if (args is not null) {
                if (args.Length > 0 && args[0] is int s) seed = s;
                if (args.Length > 1 && args[1] is int c) initialCounter = c;
            }

            _random = seed.HasValue ? new Random(seed.Value) : new Random(42);
            _counter = initialCounter;
            _currentKeystream = null;
            _offsetInBlock = 0;
        }

        public byte[] Encrypt(in byte[] input) {
            ValidateInput(_cipher, input);
            return ProcessBody(input);
        }

        public byte[] Decrypt(in byte[] input) {
            ValidateInput(_cipher, input);
            return ProcessBody(input);
        }

        private byte[] ProcessBody(byte[] input) {
            if (input.Length == 0) return Array.Empty<byte>();

            int bs = _cipher!.BlockSize;
            byte[] output = new byte[input.Length];
            int inputPos = 0;

            if (_currentKeystream != null && _offsetInBlock < bs) {
                int remainingInCurrent = bs - _offsetInBlock;
                int take = Math.Min(remainingInCurrent, input.Length);
                Array.Copy(input, 0, output, 0, take);
                for (int i = 0; i < take; i++)
                    output[i] ^= _currentKeystream[_offsetInBlock + i];

                _offsetInBlock += take;
                inputPos += take;

                if (_offsetInBlock == bs) {
                    _currentKeystream = null;
                    _offsetInBlock = 0;
                }
            }

            int remainingLength = input.Length - inputPos;
            int fullBlocks = remainingLength / bs;
            int tailLength = remainingLength % bs;

            if (fullBlocks > 0) {
                long[] steps = new long[fullBlocks];
                steps[0] = _counter;
                for (int i = 1; i < fullBlocks; i++)
                    steps[i] = _random!.Next(_MIN_STEP, _MAX_STEP) + steps[i - 1];

                Parallel.For(0, fullBlocks, i => {
                    byte[] counterBlock = CreateCounterBlock(steps[i]);
                    byte[] keystream = _cipher!.Encrypt(counterBlock);

                    int start = inputPos + i * bs;
                    for (int j = 0; j < bs; j++)
                        output[start + j] = (byte)(input[start + j] ^ keystream[j]);
                });

                _counter = steps[^1] + _random!.Next(_MIN_STEP, _MAX_STEP);
                inputPos += fullBlocks * bs;
            }

            if (tailLength > 0) {
                byte[] counterBlock = CreateCounterBlock(_counter);
                byte[] keystream = _cipher.Encrypt(counterBlock);

                int step = _random!.Next(_MIN_STEP, _MAX_STEP);
                _counter += step;

                for (int i = 0; i < tailLength; i++)
                    output[inputPos + i] = (byte)(input[inputPos + i] ^ keystream[i]);

                _currentKeystream = keystream;
                _offsetInBlock = tailLength;
            }

            return output;
        }

        private byte[] CreateCounterBlock(long counterValue) {
            int bs = _cipher!.BlockSize;
            byte[] block = new byte[bs];
            Array.Copy(_nonce!, 0, block, 0, _nonce!.Length);

            block[bs - 4] = (byte)(counterValue >> 24);
            block[bs - 3] = (byte)(counterValue >> 16);
            block[bs - 2] = (byte)(counterValue >> 8);
            block[bs - 1] = (byte)counterValue;
            return block;
        }

        private static void ValidateInput(IBlockCipher? cipher, byte[]? data) {
            if (cipher is null) throw new InvalidOperationException("Cipher not initialized.");
            if (data is null) throw new ArgumentNullException(nameof(data));
        }
    }
}

#endif
