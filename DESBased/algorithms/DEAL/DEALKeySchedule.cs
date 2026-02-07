
using DESBased.Core.Ciphers.DES;
using DESBased.Core.Context;
using DESBased.Core.Modes;
using DESBased.Core.Interfaces;
using DESBased.Core.Padding;
using DESBased.Core.Utils;

namespace DESBased.Core.Ciphers.DEAL {
public sealed class DEALKeySchedule : IKeySchedule {
    private static readonly byte[] _fixedKey = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    private static readonly byte[][] _constants =  { [0x80], [0x40], [0x20], [0x10] };
    private readonly int _keySizeBits;
    public DEALKeySchedule(int keySizeBits) {
        if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256)
            throw new ArgumentException("DEAL key size must be 128, 192 or 256 bits.");
        _keySizeBits = keySizeBits;
    }

    public byte[][] GenerateRoundKeys(in byte[] key) {
        if (key is null) throw new ArgumentNullException("The key is null.");
        if (key.Length != _keySizeBits / 8) throw new ArgumentException(
            $"DEAL key must be exactly {_keySizeBits / 8} bytes ({ _keySizeBits } bits), but was {key?.Length ?? 0} bytes."
        );
        int roundCount = _keySizeBits switch {
            128 => 6,
            192 => 6,
            256 => 8,
            _ => throw new ArgumentException("DEAL key size must be 128, 192 or 256 bits.")
        };
        int subkeyCount = _keySizeBits / 64;  // 128 -> 2, 192 -> 3, 256 -> 4
        byte[] subkeys = new byte[roundCount * 8];  // initial value of a byte is 0
        
        for (int i = 0; i < roundCount; i++) {
            Buffer.BlockCopy(key, (i * 8) % key.Length, subkeys, i * 8, 8);
            if (i >= subkeyCount) subkeys[i * 8] ^= _constants[i - subkeyCount][0];
        }
        
        CipherContext keygen = new CipherContext(
            _fixedKey, MyCipherMode.CBC, MyPadding.Zeros,
            new byte[8], new DESCipher(false)
        );
        byte[] roundKeys = keygen.EncryptAsync( subkeys ).Result;
        if ( ( roundKeys.Length / 8 ) != roundCount )
            throw new ArgumentException($"{ roundKeys.Length / 8 } != { roundCount }");
        return ByteUtils.Split( roundKeys, 8 );
    }
}
}