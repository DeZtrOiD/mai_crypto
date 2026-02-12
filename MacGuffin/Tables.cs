// https://www.schneier.com/wp-content/uploads/2016/02/paper-macguffin.pdf
namespace MacGuffin.Tables {
public static class SBoxes {
    public const int TSIZE = 1 << 16;
    // values ​​are shifted by 2 * i block
    internal static readonly ushort[][] sboxes = new ushort[8][] {
        new ushort[64] // S1
        {
            0x0002, 0x0000, 0x0000, 0x0003, 0x0003, 0x0001, 0x0001, 0x0000,
            0x0000, 0x0002, 0x0003, 0x0000, 0x0003, 0x0003, 0x0002, 0x0001,
            0x0001, 0x0002, 0x0002, 0x0000, 0x0000, 0x0002, 0x0002, 0x0003,
            0x0001, 0x0003, 0x0003, 0x0001, 0x0000, 0x0001, 0x0001, 0x0002,
            0x0000, 0x0003, 0x0001, 0x0002, 0x0002, 0x0002, 0x0002, 0x0000,
            0x0003, 0x0000, 0x0000, 0x0003, 0x0000, 0x0001, 0x0003, 0x0001,
            0x0003, 0x0001, 0x0002, 0x0003, 0x0003, 0x0001, 0x0001, 0x0002,
            0x0001, 0x0002, 0x0002, 0x0000, 0x0001, 0x0000, 0x0000, 0x0003
        },
        new ushort[64] // S2
        {
            0x000c, 0x0004, 0x0004, 0x000c, 0x0008, 0x0000, 0x0008, 0x0004,
            0x0000, 0x000c, 0x000c, 0x0000, 0x0004, 0x0008, 0x0000, 0x0008,
            0x000c, 0x0008, 0x0004, 0x0000, 0x0000, 0x0004, 0x000c, 0x0008,
            0x0008, 0x0000, 0x0000, 0x000c, 0x0004, 0x000c, 0x0008, 0x0004,
            0x0000, 0x000c, 0x0008, 0x0008, 0x0004, 0x0008, 0x000c, 0x0004,
            0x0008, 0x0004, 0x0000, 0x000c, 0x000c, 0x0000, 0x0004, 0x0000,
            0x0004, 0x000c, 0x0008, 0x0000, 0x0008, 0x0004, 0x0000, 0x0008,
            0x000c, 0x0000, 0x0004, 0x0004, 0x0000, 0x0008, 0x000c, 0x000c
        },
        new ushort[64] // S3
        {
            0x0020, 0x0030, 0x0000, 0x0010, 0x0030, 0x0000, 0x0020, 0x0030,
            0x0000, 0x0010, 0x0010, 0x0000, 0x0030, 0x0000, 0x0010, 0x0020,
            0x0010, 0x0000, 0x0030, 0x0020, 0x0020, 0x0010, 0x0010, 0x0020,
            0x0030, 0x0020, 0x0000, 0x0030, 0x0000, 0x0030, 0x0020, 0x0010,
            0x0030, 0x0010, 0x0000, 0x0020, 0x0000, 0x0030, 0x0030, 0x0000,
            0x0020, 0x0000, 0x0030, 0x0030, 0x0010, 0x0020, 0x0000, 0x0010,
            0x0030, 0x0000, 0x0010, 0x0030, 0x0000, 0x0020, 0x0020, 0x0010,
            0x0010, 0x0030, 0x0020, 0x0010, 0x0020, 0x0000, 0x0010, 0x0020
        },
        new ushort[64] // S4
        {
            0x0040, 0x00c0, 0x00c0, 0x0080, 0x0080, 0x00c0, 0x0040, 0x0040,
            0x0000, 0x0000, 0x0000, 0x00c0, 0x00c0, 0x0000, 0x0080, 0x0040,
            0x0040, 0x0000, 0x0000, 0x0040, 0x0080, 0x0000, 0x0040, 0x0080,
            0x00c0, 0x0040, 0x0080, 0x0080, 0x0000, 0x0080, 0x00c0, 0x00c0,
            0x0080, 0x0040, 0x0000, 0x00c0, 0x00c0, 0x0000, 0x0000, 0x0000,
            0x0080, 0x0080, 0x00c0, 0x0040, 0x0040, 0x00c0, 0x00c0, 0x0080,
            0x00c0, 0x00c0, 0x0040, 0x0000, 0x0040, 0x0040, 0x0080, 0x00c0,
            0x0040, 0x0080, 0x0000, 0x0040, 0x0080, 0x0000, 0x0000, 0x0080
        },
        new ushort[64] // S5
        {
            0x0000, 0x0200, 0x0200, 0x0300, 0x0000, 0x0000, 0x0100, 0x0200,
            0x0100, 0x0000, 0x0200, 0x0100, 0x0300, 0x0300, 0x0000, 0x0100,
            0x0200, 0x0100, 0x0100, 0x0000, 0x0100, 0x0300, 0x0300, 0x0200,
            0x0300, 0x0100, 0x0000, 0x0300, 0x0200, 0x0200, 0x0300, 0x0000,
            0x0000, 0x0300, 0x0000, 0x0200, 0x0100, 0x0200, 0x0300, 0x0100,
            0x0200, 0x0100, 0x0300, 0x0200, 0x0100, 0x0000, 0x0200, 0x0300,
            0x0300, 0x0000, 0x0300, 0x0300, 0x0200, 0x0000, 0x0100, 0x0300,
            0x0000, 0x0200, 0x0100, 0x0000, 0x0000, 0x0100, 0x0200, 0x0100
        },
        new ushort[64] // S6
        {
            0x0800, 0x0800, 0x0400, 0x0c00, 0x0800, 0x0000, 0x0c00, 0x0000,
            0x0c00, 0x0400, 0x0000, 0x0800, 0x0000, 0x0c00, 0x0800, 0x0400,
            0x0000, 0x0000, 0x0c00, 0x0400, 0x0400, 0x0c00, 0x0000, 0x0800,
            0x0800, 0x0000, 0x0400, 0x0c00, 0x0400, 0x0400, 0x0c00, 0x0800,
            0x0c00, 0x0000, 0x0800, 0x0400, 0x0c00, 0x0000, 0x0400, 0x0800,
            0x0000, 0x0c00, 0x0800, 0x0400, 0x0800, 0x0c00, 0x0400, 0x0800,
            0x0400, 0x0c00, 0x0000, 0x0800, 0x0000, 0x0400, 0x0800, 0x0400,
            0x0400, 0x0000, 0x0c00, 0x0000, 0x0c00, 0x0800, 0x0000, 0x0c00
        },
        new ushort[64] // S7
        {
            0x0000, 0x3000, 0x3000, 0x0000, 0x0000, 0x3000, 0x2000, 0x1000,
            0x3000, 0x0000, 0x0000, 0x3000, 0x2000, 0x1000, 0x3000, 0x2000,
            0x1000, 0x2000, 0x2000, 0x1000, 0x3000, 0x1000, 0x1000, 0x2000,
            0x1000, 0x0000, 0x2000, 0x3000, 0x0000, 0x2000, 0x1000, 0x0000,
            0x1000, 0x0000, 0x0000, 0x3000, 0x3000, 0x3000, 0x3000, 0x2000,
            0x2000, 0x1000, 0x1000, 0x0000, 0x1000, 0x2000, 0x2000, 0x1000,
            0x2000, 0x3000, 0x3000, 0x1000, 0x0000, 0x0000, 0x2000, 0x3000,
            0x0000, 0x2000, 0x1000, 0x0000, 0x3000, 0x1000, 0x0000, 0x2000
        },
        new ushort[64] // S8
        {
            0xc000, 0x4000, 0x0000, 0xc000, 0x8000, 0xc000, 0x0000, 0x8000,
            0x0000, 0x8000, 0xc000, 0x4000, 0xc000, 0x4000, 0x4000, 0x0000,
            0x8000, 0x8000, 0xc000, 0x4000, 0x4000, 0x0000, 0x8000, 0xc000,
            0x4000, 0x0000, 0x0000, 0x8000, 0x8000, 0xc000, 0x4000, 0x0000,
            0x4000, 0x0000, 0xc000, 0x4000, 0x0000, 0x8000, 0x4000, 0x4000,
            0xc000, 0x0000, 0x8000, 0x8000, 0x8000, 0x8000, 0x0000, 0xc000,
            0x0000, 0xc000, 0x0000, 0x8000, 0x8000, 0xc000, 0xc000, 0x0000,
            0xc000, 0x4000, 0x4000, 0x4000, 0x4000, 0x0000, 0x8000, 0xc000
        }
    };

    // input permutation
    internal static readonly int[][] sbits = new int[8][]
    {
        new int[] {2,5,6,9,11,13},   // S1: a2,a5, b6,b9, c11,c13
        new int[] {1,4,7,10,8,14},   // S2: a1,a4, b7,b10, c8,c14
        new int[] {3,6,8,13,0,15},   // S3: a3,a6, b8,b13, c0,c15
        new int[] {12,14,1,2,4,10},  // S4: a12,a14, b1,b2, c4,c10
        new int[] {0,10,3,14,6,12},  // S5: a0,a10, b3,b14, c6,c12
        new int[] {7,8,12,15,1,5},   // S6: a7,a8, b12,b15, c1,c5
        new int[] {9,15,5,11,2,7},   // S7: a9,a15, b5,b11, c2,c7
        new int[] {11,13,0,4,3,9}    // S8: a11,a13, b0,b4, c3,c9
    };

    // lookup masks
    public static readonly ushort[][] lookupmasks = new ushort[4][] {
        new ushort[] { 0x0036, 0x06c0, 0x6900 }, // s1+s2
        new ushort[] { 0x5048, 0x2106, 0x8411 }, // s3+s4
        new ushort[] { 0x8601, 0x4828, 0x10c4 }, // s5+s7
        new ushort[] { 0x2980, 0x9011, 0x022a }  // s6+s8
    };

    // output masks
    public static readonly ushort[] outputmasks = [ 0x000f, 0x00f0, 0x3300, 0xcc00 ];

    /* table of s-box outputs, expanded for 16 bit input.
    * this one table includes all 8 sboxes */
    private static ushort[]? _stable;
    private static readonly object _lock = new object();

    // mcg_init
    private static void InitializeStable() {
        if (_stable != null) return;
        
        lock (_lock) {
            if (_stable != null) return;
            
            _stable = new ushort[TSIZE];
            
            for (uint i = 0; i < TSIZE; i++) {
                ushort val = 0;
                for (int j = 0; j < 8; j++) {
                    int index = 
                        (int)(((i >> sbits[j][0]) & 1) |
                        (((i >> sbits[j][1]) & 1) << 1) |
                        (((i >> sbits[j][2]) & 1) << 2) |
                        (((i >> sbits[j][3]) & 1) << 3) |
                        (((i >> sbits[j][4]) & 1) << 4) |
                        (((i >> sbits[j][5]) & 1) << 5));
                    
                    val |= sboxes[j][index];
                }
                _stable[i] = val;
            }
        }
    }

    // Получение stable таблицы (ленивая инициализация)
    public static ushort[] Stable {
        get { if (_stable is null) InitializeStable();
            return _stable!;
        }
    }
    // s1+s2
    public const ushort IN00 = 0x0036;
    public const ushort IN01 = 0x06c0;
    public const ushort IN02 = 0x6900;
    public const ushort OUT0 = 0x000f;
    // s3+s4
    public const ushort IN10 = 0x5048;
    public const ushort IN11 = 0x2106;
    public const ushort IN12 = 0x8411;
    public const ushort OUT1 = 0x00f0;
    // s5+s7
    public const ushort IN20 = 0x8601;
    public const ushort IN21 = 0x4828;
    public const ushort IN22 = 0x10c4;
    public const ushort OUT2 = 0x3300;
    // s6+s8
    public const ushort IN30 = 0x2980;
    public const ushort IN31 = 0x9011;
    public const ushort IN32 = 0x022a;
    public const ushort OUT3 = 0xcc00;
}
}


/*

using MacGuffin.Tables;

namespace MacGuffin {
internal static class MacGuffinCore {
    private const int ROUNDS = 32;
    private const int KSIZE = ROUNDS * 3;
    // mcg_block_encrypt
    public static void EncryptBlock(byte[] blk, ushort[] expkey) {
        ushort r0, r1, r2, r3;
        int idx = 0;
        // copy cleartext into local words
        r0 = (ushort)(blk[0] | (blk[1] << 8));
        r1 = (ushort)(blk[2] | (blk[3] << 8));
        r2 = (ushort)(blk[4] | (blk[5] << 8));
        r3 = (ushort)(blk[6] | (blk[7] << 8));
        ushort[] value = [r0, r1, r2, r3];

        ushort[] stable = SBoxes.Stable;
        for (int i = 0; i < (ROUNDS / 4); i++) {
            for (int j = 0; j < 4; j++) {
                value[j] ^= ApplySBoxes(
                (ushort)(value[(j + 1) % 4] ^ expkey[idx++]), (ushort)(value[(j + 2) % 4] ^ expkey[idx++]),
                (ushort)(value[(j + 3) % 4] ^ expkey[idx++]), stable);
            }
        }
        for (int i = 0; i < 4; i++) {
            blk[2 * i] = (byte)(value[i] & 0xFF);
            blk[2 * i + 1] = (byte)(value[i] >> 8);
        }
    }

    // mcg_block_decrypt из оригинального кода
    public static void DecryptBlock(byte[] blk, ushort[] ek) {
        ushort r0, r1, r2, r3;
        int idx = KSIZE;
        // copy ciphertext to local words
        r0 = (ushort)(blk[0] | (blk[1] << 8));
        r1 = (ushort)(blk[2] | (blk[3] << 8));
        r2 = (ushort)(blk[4] | (blk[5] << 8));
        r3 = (ushort)(blk[6] | (blk[7] << 8));
        ushort[] value = [r0, r1, r2, r3];
        ushort[] stable = SBoxes.Stable;
        for (int i = 0; i < (ROUNDS / 4); i++) {
            for (int j = 0; j < 4; j++) {
                value[3 - j] ^= ApplySBoxes(
                (ushort)(value[(4 - j) % 4] ^ ek[--idx]), (ushort)(value[(5 - j) % 4] ^ ek[--idx]),
                (ushort)(value[(6 - j) % 4] ^ ek[--idx]), stable);
            }
        }
        // copy decrypted bits back to output
        for (int i = 0; i < 4; i++) {
            blk[2 * i] = (byte)(value[i] & 0xFF);
            blk[2 * i + 1] = (byte)(value[i] >> 8);
        }
    }

    private static ushort ApplySBoxes(ushort a, ushort b, ushort c, ushort[] stable) {
        return (ushort)(
            (SBoxes.OUT0 & stable[(a & SBoxes.IN00) | (b & SBoxes.IN01) | (c & SBoxes.IN02)]) |
            (SBoxes.OUT1 & stable[(a & SBoxes.IN10) | (b & SBoxes.IN11) | (c & SBoxes.IN12)]) |
            (SBoxes.OUT2 & stable[(a & SBoxes.IN20) | (b & SBoxes.IN21) | (c & SBoxes.IN22)]) |
            (SBoxes.OUT3 & stable[(a & SBoxes.IN30) | (b & SBoxes.IN31) | (c & SBoxes.IN32)])
        );
    }
}
}

*/