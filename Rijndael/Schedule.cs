
using Rijndael.Utils;
using DESBased.Core.Interfaces;

namespace Rijndael {
public class RijndaelKeySchedule : IKeySchedule {
    private readonly byte _gfMod;
    private readonly ushort _Nk;
    private readonly ushort _Nb;
    private readonly byte[] _Sbox;
    private readonly byte[] _invSbox;

    public RijndaelKeySchedule(byte gfMod, ref byte[] Sbox, ref byte[] invSbox, ushort Nk=4, ushort Nb=4) {
        if (Sbox is null) throw new ArgumentNullException("Sbox is null.");
        if (invSbox is null) throw new ArgumentNullException("invSbox is null.");
        if (Sbox.Length != 256) throw new ArgumentException("Sbox size must be 256 bytes.");
        if (invSbox.Length != 256) throw new ArgumentException("invSbox size must be 256 bytes.");
        if (!RijndaelHelper.IsValidNK(Nk)) throw new ArgumentException("Invalid key size.");
        if (!RijndaelHelper.IsValidNB(Nb)) throw new ArgumentException("Invalid block size.");
            
        _gfMod = gfMod;
        _Sbox = Sbox;
        _invSbox = invSbox;
        _Nk = Nk;
        _Nb = Nb;
    }
    
    public byte[][] GenerateRoundKeys(in byte[] key) {
        if (key is null) throw new ArgumentNullException("The key is null.");
        if (_Nk * 4 != key.Length) throw new ArgumentException("Invalid key size.");
        ushort Nr = RijndaelHelper.GetNr(_Nb, _Nk);
        ushort totalWords = (ushort)(_Nb * (Nr + 1));

        byte[] words = new byte[4 * totalWords];
        for (int col = 0; col < _Nk; col++) {
            words[4 * col] = key[4 * col];
            words[4 * col + 1] = key[4 * col + 1];
            words[4 * col + 2] = key[4 * col + 2];
            words[4 * col + 3] = key[4 * col + 3];
        }

        byte[] tmp = new byte[4];
        byte[] Rcon = RijndaelHelper.GetRcon(30, _gfMod);  // Nb*(Nr+1)/Nk <= 2*(14+1) = 30

        for (int i = _Nk; i < totalWords; i++) {
            int prevIdx = 4 * (i - 1);
            tmp[0] = words[prevIdx];
            tmp[1] = words[prevIdx + 1];
            tmp[2] = words[prevIdx + 2];
            tmp[3] = words[prevIdx + 3];

            if (i % _Nk == 0) {
                tmp = RijndaelHelper.leftShift(tmp, 1);
                tmp = RijndaelHelper.SubWords(tmp, 1, _Sbox, _invSbox, _gfMod, sboxInitiated: true);
                tmp[0] ^= Rcon[i / _Nk - 1];
            }
            else if ((_Nk > 6) && (i % _Nk == 4))
                tmp = RijndaelHelper.SubWords(tmp, 1, _Sbox, _invSbox, _gfMod, sboxInitiated: true);

            addKeyToWords(words, 4 * i, tmp, 4 * (i - _Nk));
        }
        byte[][] roundKeys = new byte[Nr + 1][];
        for (int round = 0; round < Nr + 1; round++) {
            roundKeys[round] = new byte[_Nb * 4];
            for (int col = 0; col < _Nb; col++) {
                int wordIndex = round * _Nb + col;
                roundKeys[round][col * 4] = words[4 * wordIndex];
                roundKeys[round][col * 4 + 1] = words[1 + 4 * wordIndex];
                roundKeys[round][col * 4 + 2] = words[2 + 4 * wordIndex];
                roundKeys[round][col * 4 + 3] = words[3 + 4 * wordIndex];
            }
        }
        return roundKeys;
    }

    private static void addKeyToWords(byte[] words, int targetIdx, byte[] tmp, int prevKeyIdx) {
        words[targetIdx] = (byte)(words[prevKeyIdx] ^ tmp[0]);
        words[targetIdx + 1] = (byte)(words[prevKeyIdx + 1] ^ tmp[1]);
        words[targetIdx + 2] = (byte)(words[prevKeyIdx + 2] ^ tmp[2]);
        words[targetIdx + 3] = (byte)(words[prevKeyIdx + 3] ^ tmp[3]);
    }
}
}
