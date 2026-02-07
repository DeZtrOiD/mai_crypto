
using System.Buffers.Binary;

namespace DESBased.Core.Utils {
public static class ByteUtils {
    public static byte[] Xor(in byte[] a, in byte[] b) {
        if ( a is null ) throw new ArgumentNullException("First array must not be null.");
        if ( b is null ) throw new ArgumentNullException("Second array must not be null.");

        int minLength = Math.Min(a.Length, b.Length);
        byte[] result = new byte[minLength];
        for (int i = 0; i < minLength; i++) result[i] = (byte)(a[i] ^ b[i]);
        return result;
    }

    public static byte[] Concat(in byte[][] blocks) {
        if ( blocks is null ) throw new ArgumentNullException("The blocks is null.");
        if ( blocks.Length == 0 ) return Array.Empty<byte>();

        int totalLength = 0;
        foreach ( byte[] block in blocks ) totalLength += block?.Length ?? 0;

        byte[] result = new byte[totalLength];
        int offset = 0;
        foreach ( byte[] block in blocks ) {
            if (block is not null && block.Length > 0) {
                Buffer.BlockCopy(block, 0, result, offset, block.Length);
                offset += block.Length;
            }
        }
        return result;
    }

    public static byte[][] Split(in byte[] data, int blockSize) {
        if ( data is null ) throw new ArgumentNullException("The date is null.");
        if ( blockSize <= 0 ) throw new ArgumentException("Block size must be positive.");
        if ( data.Length == 0 ) return Array.Empty<byte[]>();
        
        int blockCount = (data.Length + blockSize - 1) / blockSize;
        byte[][] blocks = new byte[blockCount][];
        
        for (int i = 0; i < blockCount; i++) {
            int start = i * blockSize;
            int length = Math.Min(blockSize, data.Length - start);
            blocks[i] = new byte[length];
            Buffer.BlockCopy(data, start, blocks[i], 0, length);
        }
        return blocks;
    }

    // 2^(64)*(blockSize=64+) Is All You Need
    public static byte[] AddBigEndian2pow8(byte[] block, ulong value) {
        if ( block is null ) throw new ArgumentNullException("The block is null");
        if ( block.Length < 8 ) throw new ArgumentException("The block size must be at least 8 byte");

        int offset = block.Length - 8;
        ulong result = BinaryPrimitives.ReadUInt64BigEndian(block.AsSpan(offset, 8));
        result += value;
        BinaryPrimitives.WriteUInt64BigEndian(block.AsSpan(offset, 8), result);
        return block;
    }

    public static byte[] AddMod2N(in byte[] a, in byte[] b) {
        if (a.Length != b.Length) throw new ArgumentException("Blocks must have same size.");

        byte[] res = new byte[a.Length];
        ulong carry = 0;

        for (int i = a.Length - 1; i >= 0; i--) {
            ulong sum = (ulong)a[i] + b[i] + carry;
            res[i] = (byte)(sum & 0xFF);
            carry = sum >> 8;
        }
        return res;
    }

    public static byte[] MultiplyMod2N(byte[] value, uint multiplier) {
        if ( value is null ) throw new ArgumentNullException("The value is null");
        if ( multiplier == 0 ) return new byte[value.Length];
        if ( multiplier == 1 ) return (byte[])value.Clone();

        byte[] result = new byte[value.Length];
        ulong carry = 0;

        for (int i = value.Length - 1; i >= 0; i--)  {
            ulong product = (value[i] * (ulong)multiplier) + carry;
            result[i] = (byte)(product & 0xFF);
            carry = product >> 8;
        }
        return result;
    }
}
}
