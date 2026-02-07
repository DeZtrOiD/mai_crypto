
using DESBased.Core.Interfaces;
using DESBased.Core.Permutation;
using System.Buffers.Binary;

namespace DESBased.Core.Ciphers.DES {
public sealed class DESKeySchedule : IKeySchedule {

    private readonly bool _parity;

    public DESKeySchedule(bool parity=true) => _parity = parity;

    public byte[][] GenerateRoundKeys(in byte[] key) {
        if ( key is null ) throw new ArgumentException("DES key is null.");
        if ( key.Length != 8 ) throw new ArgumentException("DES key must be 8 bytes.");

        for (int i = 0; _parity && (i < 8); i++) {
            bool parity = true;
            for (int j = 0; j < 8; j++) parity ^= (key[i] & (1 << (7 - j))) != 0;
            if (parity) throw new ArgumentException($"Parity error in byte {i}.");
        }

        byte[] cd56 = Permutation.Permutation.Permute(key, DESTables.PC1);
        (uint c28, uint d28) = ExtractCAndD(cd56);

        byte[][] roundKeys = new byte[16][];
        for (int i = 0; i < 16; i++) {
            c28 = RotateLeft28(c28, DESTables.SHIFTS[i]);
            d28 = RotateLeft28(d28, DESTables.SHIFTS[i]);
            byte[] cd56Rotated = ConcatBits28(c28, d28);
            roundKeys[i] = Permutation.Permutation.Permute(cd56Rotated, DESTables.PC2);
        }
        return roundKeys;
    }

    private static (uint c28, uint d28) ExtractCAndD(in byte[] pc1Result) {
        return (Extract28Bits(pc1Result, 0), Extract28Bits(pc1Result, 28));
    }

    private static uint Extract28Bits(in byte[] data, int startBit) {
        if ( data is null ) throw new ArgumentNullException("Data array is null");
        if ( data.Length != 7 ) throw new ArgumentException("Data array must have 7 bytes after PC1");
        if ( startBit == 0 ) {
            return (BinaryPrimitives.ReadUInt32BigEndian(data) >> 4) & 0x0FFFFFFF;
        } else if (startBit == 28) {
            uint combined = ((uint)data[3] << 24) | ((uint)data[4] << 16);
            combined |= ((uint)data[5] << 8) | data[6];
            return combined  & 0x0FFFFFFF;
        } else throw new ArgumentOutOfRangeException("The start bit must be 1 or 28.");
    }

    private static byte[] ConcatBits28(uint c28, uint d28) {
        byte[] result = new byte[7];
        ulong cd56 = ((ulong)(c28) << 28) | d28;
        for (int i = 0; i < 7; i++) {
            result[i] = (byte)(cd56 >>> (48 - i * 8));
        }
        return result;
    }

    private static uint RotateLeft28(uint value, int shifts) {
        shifts %= 28;
        if ( shifts == 0 ) return value;
        const uint MASK28 = 0x0FFFFFFF;
        return ((value << shifts) | (value >>> (28 - shifts))) & MASK28;
    }
}
}
