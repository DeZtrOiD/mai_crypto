
using DESBased.Core.Interfaces;
using DESBased.Core.Ciphers.DES;

namespace DESBased.Core.Ciphers.DEAL {
public sealed class DESAsRoundFunction : IRoundFunction {
    public DESAsRoundFunction(){}
    public byte[] Transform(byte[] halfBlock, in byte[] roundKey) {
        if ( halfBlock is null ) throw new ArgumentNullException("Half block is null.");
        if ( halfBlock.Length != 8 ) throw new ArgumentException("Half block must be 8 bytes.");

        if ( roundKey is null ) throw new ArgumentNullException("Round key is null.");
        if ( roundKey.Length != 8 ) throw new ArgumentException("Round key must be 8 bytes.");

        var des = new DESCipher(false);
        des.Init(roundKey);
        return des.Encrypt(halfBlock);
    }
}
}
