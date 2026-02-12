// As requested — no more, no less
using DESBased.Core.Interfaces;
using Rijndael.Galois;
using Rijndael.Utils;

// https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
namespace Rijndael {
public class RijndaelBlockCipher : IBlockCipher {
    private readonly byte _gfMod;
    private readonly RijndaelKeySchedule _keySchedule;
    private readonly RijndaelRoundFunction _forwardRoundFunc;
    private readonly RijndaelRoundFunction _backwardRoundFunc;
    private byte[][]? _roundKeys;
    private readonly byte[] _Sbox;
    private readonly byte[] _invSbox;
    private readonly ushort _Nb;
    private readonly ushort _Nk;
    private readonly ushort _Nr;
    public int BlockSize => _Nb * 4;

    public RijndaelBlockCipher(ushort blockSize, ushort keySize, byte gfMod) {
        if (!RijndaelHelper.IsValidBlockSize(blockSize)) throw new ArgumentException("Invalid block size");
        if (!RijndaelHelper.IsValidKeySize(keySize)) throw new ArgumentException("Invalid key size");
        if (!GF2NCalc.Irreducible(gfMod)) throw new ArgumentException("The polynomial must be irreducible.");

        _gfMod = gfMod;
        _Sbox = new byte[256];
        _invSbox = new byte[256];
        _Nb = RijndaelHelper.GetNb(blockSize);
        _Nk = RijndaelHelper.GetNk(keySize);
        _Nr = RijndaelHelper.GetNr(_Nb, _Nk);
        _roundKeys = null;
        
        // Two zero-related values ​​are initialized.
        // This is necessary to treat other zero values in Sbox ​​as uninitialized.
        _Sbox[0] = RijndaelHelper.AffineTransform(GF2NCalc.Inv(0, _gfMod));
        _invSbox[_Sbox[0]] = 0;
        _invSbox[0] = GF2NCalc.Inv(RijndaelHelper.InverseAffineTransform(0), _gfMod);
        _Sbox[_invSbox[0]] = 0;

        _keySchedule = new RijndaelKeySchedule(_gfMod, ref _Sbox, ref _invSbox, _Nk, _Nb);
        _forwardRoundFunc = new RijndaelRoundFunction(_Nb, _gfMod, ref _Sbox, ref _invSbox);
        _backwardRoundFunc = new RijndaelRoundFunction(_Nb, _gfMod, ref _Sbox, ref _invSbox, true);
    }

    public void Init(in byte[] key) {
        if (key.Length != _Nk * 4) throw new ArgumentException($"Key must be {_Nk * 4} bits");
        _roundKeys = _keySchedule.GenerateRoundKeys(key);
    }
    
    public byte[] Encrypt(in byte[] block) {
        if (_roundKeys == null)
            throw new InvalidOperationException("Cipher not initialized. Call Init first.");
        if (block.Length != BlockSize)
            throw new ArgumentException($"Block must be {BlockSize} bits");
        byte[] state = (byte[])block.Clone();
        state = RijndaelHelper.AddRoundKey(state, _Nb, _roundKeys[0], _Nb);
        for (int i = 1; i < _Nr; i++) {
            state = _forwardRoundFunc.Transform(state, _roundKeys[i]);
        }
        state = RijndaelHelper.SubWords(state, _Nb, _Sbox, _invSbox, _gfMod, sboxInitiated: true);
        state = RijndaelHelper.ShiftRow(state, _Nb);
        return RijndaelHelper.AddRoundKey(state, _Nb, _roundKeys[_Nr], _Nb);
    }
    
    public byte[] Decrypt(in byte[] block) {
        if (_roundKeys == null)
            throw new InvalidOperationException("Cipher not initialized. Call Init first.");
        if (block.Length != BlockSize)
            throw new ArgumentException($"Block must be {BlockSize} bits");
        byte[] state = (byte[])block.Clone();
        state = RijndaelHelper.AddRoundKey(state, _Nb, _roundKeys[_Nr], _Nb);
        state = RijndaelHelper.ShiftRow(state, _Nb, true);
        state = RijndaelHelper.SubWords(state, _Nb, _Sbox, _invSbox, _gfMod, inverse: true, sboxInitiated: true);
        for (int i = _Nr - 1; i > 0; i--) {
            state = _backwardRoundFunc.Transform(state, _roundKeys[i]);
        }
        return RijndaelHelper.AddRoundKey(state, _Nb, _roundKeys[0], _Nb);
    }
}
}
