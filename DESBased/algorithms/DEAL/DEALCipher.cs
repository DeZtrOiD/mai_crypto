
using DESBased.Core.Interfaces;

namespace DESBased.Core.Ciphers.DEAL {
public sealed class DEALCipher : FeistelNetwork, IBlockCipher {
    public DEALCipher(int keySizeBits)
        : base(new DEALKeySchedule(keySizeBits), new DESAsRoundFunction()) {

        _roundCount = keySizeBits switch {
            128 => 6,
            192 => 6,
            256 => 8,
            _ => throw new ArgumentException("DEAL key size must be 128, 192 or 256 bits.", nameof(keySizeBits))
        };
        _blockSize = 16;
    }

    public override int BlockSize { get => _blockSize; }
    public override int RoundCount { get => _roundCount; }
    public override void Init(in byte[] key) => base.Init(key);
    public override byte[] Encrypt(in byte[] block) => base.Decrypt(block);
    public override byte[] Decrypt(in byte[] block) => base.Encrypt(block);
}
}
