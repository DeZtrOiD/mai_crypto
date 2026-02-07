
using DESBased.Core.Interfaces;
using DESBased.Core.Utils;

namespace DESBased.Core.Ciphers {
public class FeistelNetwork : IBlockCipher {
    private readonly IKeySchedule _keySchedule;
    private readonly IRoundFunction _roundFunction;
    protected int _blockSize;
    protected int _roundCount;
    private byte[][]? _roundKeys;

    public FeistelNetwork(
        IKeySchedule keySchedule,
        IRoundFunction roundFunction
    ) {
        _keySchedule = keySchedule ??
            throw new ArgumentNullException("The Feistel network requires a key schedule.");
        _roundFunction = roundFunction ??
            throw new ArgumentNullException("The Feistel network requires a round function.");
        _roundCount = 16;
    }

    public virtual int BlockSize {
        get { return _blockSize; }
        set {
            if ( value <= 0 )
                throw new ArgumentOutOfRangeException("The block size must be even and greater than 0.");
            _blockSize = value;
        }
    }

    public virtual int RoundCount {
        get { return _roundCount; }
        set {
            if ( value <= 0 )
                throw new ArgumentOutOfRangeException("The number of rounds must be greater than 0.");
            _roundCount = value;
        }
    }

    public virtual void Init(in byte[] key) {
        if ( key is null ) throw new ArgumentNullException("The key cannot be null.");
        if ( key.Length == 0 ) throw new ArgumentException("The key cannot be empty.");
        _roundKeys = _keySchedule.GenerateRoundKeys(key);

        if (_roundKeys is null || _roundKeys.Length != RoundCount)
            throw new InvalidOperationException(
                $"Key schedule must generate exactly {RoundCount} round keys, but generated {_roundKeys?.Length ?? 0}."
        );
    }

    public virtual byte[] Encrypt(in byte[] block) {
        ValidateState( block );
        var halfSize = BlockSize / 2;

        var left = new byte[halfSize];
        var right = new byte[halfSize];
        Buffer.BlockCopy( block, 0, left, 0, halfSize );
        Buffer.BlockCopy( block, halfSize, right, 0, halfSize );

        for (int i = 0; i < RoundCount; i++) {
            var temp = left;
            var fOutput = _roundFunction.Transform(right, _roundKeys![i]);
            left = right;
            right = ByteUtils.Xor(temp, fOutput);
        }
        return ByteUtils.Concat([left, right]);
    }

    public virtual byte[] Decrypt(in byte[] block) {
        ValidateState( block );
        var halfSize = BlockSize / 2;

        var left = new byte[halfSize];
        var right = new byte[halfSize];
        Buffer.BlockCopy( block, 0, left, 0, halfSize );
        Buffer.BlockCopy( block, halfSize, right, 0, halfSize );

        for (int i = RoundCount - 1; i >= 0; i--) {
            var temp = right;
            var fOutput = _roundFunction.Transform(left, _roundKeys![i]);
            right = left;
            left = ByteUtils.Xor(temp, fOutput);
        }
        return ByteUtils.Concat([left, right]);
    }

    protected virtual void ValidateState(in byte[] block) {
        if ( _roundKeys is null )
            throw new InvalidOperationException("Cipher not initialized. Call Initialize() first.");
        if (_roundKeys is null || _roundKeys.Length != RoundCount)
            throw new InvalidOperationException(
                $"Key schedule must generate exactly { RoundCount } round keys, but generated { _roundKeys?.Length ?? 0 }.");
        ValidateBlock(block);
    }

    protected virtual void ValidateBlock(in byte[] block) {
        if ( block is null ) throw new ArgumentNullException("Block cannot be null.");
        if (block.Length != BlockSize)
            throw new ArgumentException($"Block size must be exactly { BlockSize } bytes, but was { block.Length }.");
    }
}
}
