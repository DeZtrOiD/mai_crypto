
using DESBased.Core.Interfaces;

namespace DESBased.Core.Modes {
public static class CipherModeFactory {
    public static ICipherMode Create(MyCipherMode mode) {
        return mode switch {
            MyCipherMode.ECB => new ECBMode(),
            MyCipherMode.CBC => new CBCMode(),
            MyCipherMode.PCBC => new PCBCMode(),
            MyCipherMode.CFB => new CFBMode(),
            MyCipherMode.OFB => new OFBMode(),
            MyCipherMode.CTR => new CTRMode(),
            MyCipherMode.RD => new RandomDeltaMode(),
            _ => throw new NotSupportedException($"Cipher mode { mode } is not supported.")
        };
    }
}
}
