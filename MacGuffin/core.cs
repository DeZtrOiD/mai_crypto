
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
        ushort r0, r1, r2, r3, a, b, c;
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
                c = (ushort)(value[(6 - j) % 4] ^ ek[--idx]);
                b = (ushort)(value[(5 - j) % 4] ^ ek[--idx]);
                a = (ushort)(value[(4 - j) % 4] ^ ek[--idx]);
                value[3 - j] ^= ApplySBoxes(a, b, c, stable);
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

