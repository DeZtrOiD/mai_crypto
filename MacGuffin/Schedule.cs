
using MacGuffin.Tables;

namespace MacGuffin.Schedule {
public class MacGuffinKeySchedule {
    private const int ROUNDS = 32;
    private const int KSIZE = ROUNDS * 3;
    private const int KEY_SIZE = 16;

    public ushort[] GenerateRoundKeys(in byte[] key) {
        if (key is null) throw new ArgumentNullException("Key is null");
        if (key.Length != KEY_SIZE) throw new ArgumentException($"Key must be {KEY_SIZE} bytes (128 bits)");

        ushort[] expandedKey = new ushort[KSIZE];
        
        // mcg_init()
        _ = SBoxes.Stable;

        // Two halves of the key, 8 bytes each
        byte[][] k = new byte[2][];
        k[0] = new byte[8];
        k[1] = new byte[8];
        
        Buffer.BlockCopy(key, 0, k[0], 0, 8);
        Buffer.BlockCopy(key, 8, k[1], 0, 8);

        for (int i = 0; i < KSIZE; i++) expandedKey[i] = 0;

        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 32; j++) {
                // mcg_block_encrypt(k[i], ek)
                byte[] block = (byte[])k[i].Clone();
                MacGuffinCore.EncryptBlock(block, expandedKey);
                
                // ek->val[j*3] ^= k[i][0] | (k[i][1]<<8);
                expandedKey[j * 3] ^= (ushort)(k[i][0] | (k[i][1] << 8));
                expandedKey[j * 3 + 1] ^= (ushort)(k[i][2] | (k[i][3] << 8));
                expandedKey[j * 3 + 2] ^= (ushort)(k[i][4] | (k[i][5] << 8));
            }
        }
        return expandedKey;
    }
}
}
