
using DESBased.Core.Interfaces;
using Rijndael.Utils;

namespace Rijndael {
public class RijndaelRoundFunction : IRoundFunction {
    private readonly byte _gfMod;
    private readonly byte[] _Sbox;
    private readonly byte[] _invSbox;
    private readonly bool _inverse;
    private readonly ushort _Nb;
    public RijndaelRoundFunction(ushort Nb, byte gfMod, ref byte[] Sbox, ref byte[] invSbox, bool inverse=false) {
        if (Sbox is null) throw new ArgumentNullException("Sbox is null.");
        if (invSbox is null) throw new ArgumentNullException("invSbox is null.");
        if (Sbox.Length != 256) throw new ArgumentException("Sbox size must be 256 bytes.");
        if (invSbox.Length != 256) throw new ArgumentException("invSbox size must be 256 bytes.");

        if (!RijndaelHelper.IsValidNB(Nb)) throw new ArgumentException("Invalid block size.");

        _gfMod = gfMod;
        _Sbox = Sbox;
        _invSbox = invSbox;
        _inverse = inverse;
        _Nb = Nb;
    }
    
    public byte[] Transform(byte[] state, in byte[] roundKey) {
        if (state is null) throw new ArgumentNullException("The state is null.");
        if (roundKey is null) throw new ArgumentNullException("The key is null.");
        if (state.Length != _Nb * 4) throw new ArgumentException("Incorrect size for this state.");
        if (roundKey.Length != _Nb * 4) throw new ArgumentException("Incorrect size for this key.");

        if (!_inverse) {
            state = RijndaelHelper.SubWords(state, _Nb, _Sbox, _invSbox, _gfMod);
            state = RijndaelHelper.ShiftRow(state, _Nb);
            state = RijndaelHelper.MixColumns(state, _Nb,_gfMod);
            state = RijndaelHelper.AddRoundKey(state, _Nb, roundKey, _Nb);
        } else {
            state = RijndaelHelper.AddRoundKey(state, _Nb, roundKey, _Nb);
            state = RijndaelHelper.MixColumns(state, _Nb, _gfMod, true);
            state = RijndaelHelper.ShiftRow(state, _Nb, true);
            state = RijndaelHelper.SubWords(state, _Nb, _Sbox, _invSbox, _gfMod, true);
        }

        return state;
    }
}
}
