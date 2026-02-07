
using DESBased.Core.Interfaces;
using DESBased.Core.Permutation;
using DESBased.Core.Utils;
using System.Buffers.Binary;

namespace DESBased.Core.Ciphers.DES {
public sealed class DESRoundFunction : IRoundFunction {
    public byte[] Transform(in byte[] halfBlock, in byte[] roundKey) {
        if ( halfBlock is null ) throw new ArgumentNullException( nameof(halfBlock) );
        if ( roundKey is null ) throw new ArgumentNullException( nameof(roundKey) );
        if (halfBlock.Length != 4 || roundKey.Length != 6)
            throw new ArgumentException("Invalid block/key size for DES round function.");

        byte[] expanded = Permutation.Permutation.Permute(halfBlock, DESTables.E);  // 32->48
                
        byte[] sBoxOutput = ApplySBoxes(ByteUtils.Xor(expanded, roundKey));  // 48Xor->32
        
        return Permutation.Permutation.Permute(sBoxOutput, DESTables.P); // 32->32
    }

    private static byte[] ApplySBoxes(in byte[] input48) {
        Span<byte> input64 = stackalloc byte[8];
        input48.CopyTo(input64.Slice(2, 6));

        ulong input = BinaryPrimitives.ReadUInt64BigEndian(input64);
        uint output = 0;
        for (int i = 0; i < 8; i++) {
            int bits = (int)((input >> (42 - (i * 6))) & 0x3F);  // Takes a 6-bit block
            int row = ((bits & 0x20) >> 4) | (bits & 0x01);  // 0/5 bit -> string
            int col = (bits >> 1) & 0x0F;  // 1-4 bit -> column
            output = (output << 4) | DESTables.S_BOXES[i][row * 16 + col];
        }
        byte[] output32 = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(output32, output);
        return output32;
    }
}
}
