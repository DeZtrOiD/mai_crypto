
using DESBased.Core.Interfaces;
using DESBased.Core.Permutation;
using DESBased.Core.Utils;

namespace DESBased.Core.Ciphers.DES {
public sealed class DESCipher : FeistelNetwork, IBlockCipher {
    public DESCipher(bool parity = true) : base(new DESKeySchedule(parity), new DESRoundFunction()) {
        _blockSize = 8;
        _roundCount = 16;
    }
    public override int BlockSize { get => _blockSize; }
    public override int RoundCount { get => _roundCount; }
    public override void Init(in byte[] key) => base.Init(key);
    public override byte[] Encrypt(in byte[] block) {
        ValidateBlock( block );

        byte[] ip = Permutation.Permutation.Permute(block, DESTables.IP);
        byte[] feistel = base.Encrypt(ip);
        byte[][] blocks = ByteUtils.Split(feistel, feistel.Length/2);
        feistel = ByteUtils.Concat([blocks[1], blocks[0]]); // L\R swap

        return Permutation.Permutation.Permute(feistel, DESTables.IP_INVERSE);
    }

    public override byte[] Decrypt(in byte[] block) {
        ValidateBlock( block );
        
        byte[] ip = Permutation.Permutation.Permute(block, DESTables.IP);
        byte[][] blocks = ByteUtils.Split(ip, ip.Length/2);
        byte[] feistel = base.Decrypt(ByteUtils.Concat([blocks[1], blocks[0]]));
        // L\R swap + decrypt

        return Permutation.Permutation.Permute(feistel, DESTables.IP_INVERSE);
    }
}
}
