
using Rijndael.Galois;

namespace Rijndael.Utils {
public static class RijndaelHelper {
    public const int BLOCK_SIZE_128 = 128;
    public const int BLOCK_SIZE_192 = 192;
    public const int BLOCK_SIZE_256 = 256;
    public const int KEY_SIZE_128 = 128;
    public const int KEY_SIZE_192 = 192;
    public const int KEY_SIZE_256 = 256;
    public static ushort GetNb(ushort blockSize) => (ushort)(blockSize / 32);
    public static ushort GetNk(ushort keySize) => (ushort)(keySize / 32);
    public static ushort GetNr(ushort Nb, ushort Nk) =>
        (ushort)Math.Min(14, Math.Max(Nb, Nk) + 6);

    // https://en.wikipedia.org/wiki/AES_key_schedule
    public static byte[] GetRcon(ushort count, byte mod) {
        if (count > 0x80) throw new ArgumentException("This size is not supported.");  // It can be supported, but there is no need.
        byte[] Rcon = new byte[count];
        Rcon[0] = 1;
        for (int i = 1; i < count; i++) Rcon[i] = GF2NCalc.MulMod(Rcon[i - 1], 2, mod);
        return Rcon;
    }

    private static (int, int, int) GetShiftCoeff(int Nb) {
        return Nb switch {
            4 => (1, 2, 3),
            6 => (1, 2, 3),
            8 => (1, 3, 4),
            _ => throw new ArgumentException("This size is not supported.")
        };
    }

    public static byte[] ShiftRow(byte[] state, ushort Nb, bool inverse=false) {
        if (state is null) throw new ArgumentNullException("The state is null.");
        if ((state.Length != 4 * Nb) || !IsValidNB(Nb)) throw new ArgumentException("Incorrect size for this state.");

        var (c1, c2, c3) = GetShiftCoeff(Nb);
        if (inverse) { c1 = Nb-c1; c2= Nb-c2; c3 = Nb-c3; };

        for (int j = 1; j < 4; j++) {
            int c = ((int[])[c1, c2, c3])[j - 1];
            byte[] temp = new byte[c];
            for (int i = 0; i < c; i++) temp[i] = state[4 * i + j];
            for (int i = 0; i < Nb - c; i++) state[4 * i + j] = state[4 * (i + c) + j];
            for (int i = 0; i < c; i++) state[4 * (Nb - c + i) + j] = temp[i];
        }
        return state;
    }

    public static byte[] AddRoundKey(byte[] state, ushort Nb, byte[] key, ushort Nk) {
        if (state is null) throw new ArgumentNullException("The state is null.");
        if (key is null) throw new ArgumentNullException("The key is null.");
        if (Nb != Nk) throw new ArgumentException("The dimensions of the state and the key do not match.");
        if (state.Length != 4 * Nb || key.Length != 4 * Nk) throw new ArgumentException("Incorrect size for this state or key.");
        if ((Nk != 1 && !IsValidNK(Nk)) || (Nb != 1 && !IsValidNB(Nb))) throw new ArgumentException("Incorrect dimension.");

        for (int i = 0; i < Nb; i ++) {
            state[4 * i] = GF2NCalc.Add(state[4 * i], key[4 * i]);
            state[4 * i + 1] = GF2NCalc.Add(state[4 * i + 1], key[4 * i + 1]);
            state[4 * i + 2] = GF2NCalc.Add(state[4 * i + 2], key[4 * i + 2]);
            state[4 * i + 3] = GF2NCalc.Add(state[4 * i + 3], key[4 * i + 3]);
        }
        return state;
    }

    // https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
    public static byte[] MixColumns(byte[] state, ushort Nb, byte mod = 0x1B, bool inverse=false) {
        if (state is null) throw new ArgumentNullException("The state is null.");
        if (state.Length != 4 * Nb) throw new ArgumentException("Incorrect size for this state.");
        if (!IsValidNB(Nb)) throw new ArgumentException("Incorrect dimension.");

        for (int i = 0; i < Nb; i++) {
            byte a0 = state[4 * i], a1 = state[1 + 4 * i], a2 = state[2 + 4 * i], a3 = state[3 + 4 * i];
            if (!inverse) {  // c(x) = ‘03’x^3 + ‘01’x^2 + ‘01’x + ‘02’; c(x) * a(x) mod X^4 + 1
                state[4 * i] = (byte)(GF2NCalc.MulMod(0x02, a0, mod) ^ GF2NCalc.MulMod(0x03, a1, mod) ^
                    GF2NCalc.MulMod(0x01, a2, mod) ^ GF2NCalc.MulMod(0x01, a3, mod));

                state[1 + 4 * i] = (byte)(GF2NCalc.MulMod(0x01, a0, mod) ^ GF2NCalc.MulMod(0x02, a1, mod) ^
                    GF2NCalc.MulMod(0x03, a2, mod) ^ GF2NCalc.MulMod(0x01, a3, mod));

                state[2 + 4 * i] = (byte)(GF2NCalc.MulMod(0x01, a0, mod) ^ GF2NCalc.MulMod(0x01, a1, mod) ^
                    GF2NCalc.MulMod(0x02, a2, mod) ^ GF2NCalc.MulMod(0x03, a3, mod));

                state[3 +  4* i] = (byte)(GF2NCalc.MulMod(0x03, a0, mod) ^ GF2NCalc.MulMod(0x01, a1, mod) ^
                    GF2NCalc.MulMod(0x01, a2, mod) ^ GF2NCalc.MulMod(0x02, a3, mod));
            } else {  // d(x) = ‘0B’ x^3 + ‘0D’ x^2 + ‘09’ x + ‘0E’; d(x) * a(x) mod X^4 + 1
                state[4 * i] = (byte)(GF2NCalc.MulMod(0x0E, a0, mod) ^ GF2NCalc.MulMod(0x0B, a1, mod) ^
                    GF2NCalc.MulMod(0x0D, a2, mod) ^ GF2NCalc.MulMod(0x09, a3, mod));

                state[1 + 4 * i] = (byte)(GF2NCalc.MulMod(0x09, a0, mod) ^ GF2NCalc.MulMod(0x0E, a1, mod) ^
                    GF2NCalc.MulMod(0x0B, a2, mod) ^ GF2NCalc.MulMod(0x0D, a3, mod));

                state[2 + 4 * i] =  (byte)(GF2NCalc.MulMod(0x0D, a0, mod) ^ GF2NCalc.MulMod(0x09, a1, mod) ^
                    GF2NCalc.MulMod(0x0E, a2, mod) ^ GF2NCalc.MulMod(0x0B, a3, mod));

                state[3 + 4 * i] = (byte)(GF2NCalc.MulMod(0x0B, a0, mod) ^ GF2NCalc.MulMod(0x0D, a1, mod) ^
                    GF2NCalc.MulMod(0x09, a2, mod) ^ GF2NCalc.MulMod(0x0E, a3, mod));
            }
        }
        return state;
    }

    public static byte[] leftShift(byte[] words, ushort cols) {
        if (words is null) throw new ArgumentException("The state is null.");
        if (words.Length != 4 * cols) throw new ArgumentException("Incorrect size for words array.");
        if (!IsValidNB(cols) && (cols < 44) && (cols != 1)) throw new ArgumentException("Incorrect dimension."); // Nb*(Nr + 1) >= 44

        for (int i = 0; i < cols; i++) {
            (words[4 * i], words[4 * i + 1], words[4 * i + 2], words[4 * i + 3]) =
                (words[4 * i + 1], words[4 * i + 2], words[4 * i + 3], words[4 * i]);
        }
        return words;
    }

    public static byte[] SubWords(byte[] state, ushort cols, byte[] Sbox, byte[] invSbox, byte mod=0x1B, bool inverse=false, bool sboxInitiated=false) {
        if (state is null) throw new ArgumentNullException("The state is null.");
        if (state.Length != cols * 4) throw new ArgumentException("Incorrect size for this state.");
        if (!IsValidNB(cols) && (cols < 44) && (cols != 1)) throw new ArgumentException("Incorrect dimension."); // Nb*(Nr + 1) >= 44
        
        if (Sbox is null) throw new ArgumentNullException("Sbox is null.");
        if (invSbox is null) throw new ArgumentNullException("InvSbox is null.");
        if (Sbox.Length != 256) throw new ArgumentException("Sblock must be 256 bytes.");
        if (invSbox.Length != 256) throw new ArgumentException("invSblock must be 256 bytes.");
        
        if (!sboxInitiated) {
            // Otherwise, it's hard to track the state of each Inv/Sbox cell.
            byte sboxValue = AffineTransform(GF2NCalc.Inv(0, mod));
            Sbox[0] = sboxValue;
            invSbox[sboxValue] = 0;
            byte invValue = GF2NCalc.Inv(InverseAffineTransform(0), mod);
            invSbox[0] = invValue;
            Sbox[invValue] = 0;
        }

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < cols; j++) {
                byte input = state[i + 4 * j];
                if (inverse) {
                    if (invSbox[input] == 0 && Sbox[0] != input) {
                        byte invValue = GF2NCalc.Inv(InverseAffineTransform(input), mod);
                        invSbox[input] = invValue;
                        Sbox[invValue] = input;
                    }
                    state[i + 4 * j] = invSbox[input];
                } else {
                    if (Sbox[input] == 0 && invSbox[0] != input) {
                        byte sboxValue = AffineTransform(GF2NCalc.Inv(input, mod));
                        Sbox[input] = sboxValue;
                        invSbox[sboxValue] = input;
                    }
                    state[i + 4 * j] = Sbox[input];
                }
            }
        }
        return state;
    }

    // https://en.wikipedia.org/wiki/Rijndael_S-box
    public static byte AffineTransform(byte b) {
        byte s = 0;
        byte c = 0x63;  // 0b0110_0011;
        for (int i = 0; i < 8; i++) {
            byte bit = (byte)(  // b'i = bi^b((i+4)mod8)^b((i+5)mod8)^b((i+6) mod 8)^b((i+7) mod 8)^ci
                ((b >> i) & 1) ^ ((b >> ((i + 4) % 8)) & 1) ^
                ((b >> ((i + 5) % 8)) & 1) ^ ((b >> ((i + 6) % 8)) & 1) ^
                ((b >> ((i + 7) % 8)) & 1) ^ ((c >> i) & 1)
            );
            s |= (byte)(bit << i);
        }
        return s;
    }

    // https://en.wikipedia.org/wiki/Rijndael_S-box
    public static byte InverseAffineTransform(byte s) {
        byte b = 0;
        byte c = 0x05;  // 0b0000_0101;
        for (int i = 0; i < 8; i++) {
            byte bit = (byte)(
                ((s >> ((i + 2) % 8)) & 1) ^ ((s >> ((i + 5) % 8)) & 1) ^
                ((s >> ((i + 7) % 8)) & 1) ^ ((c >> i) & 1)
            );
            b |= (byte)(bit << i);
        }
        return b;
    }

    public static bool IsValidBlockSize(int blockSize) => blockSize == BLOCK_SIZE_128 || 
        blockSize == BLOCK_SIZE_192 || blockSize == BLOCK_SIZE_256;
    
    public static bool IsValidKeySize(int keySize) => keySize == KEY_SIZE_128 ||
        keySize == KEY_SIZE_192 || keySize == KEY_SIZE_256;

    public static bool IsValidNK(ushort Nk) => Nk == 4 || Nk == 6 || Nk == 8;
    public static bool IsValidNB(ushort Nb) => Nb == 4 || Nb == 6 || Nb == 8;
}
}
