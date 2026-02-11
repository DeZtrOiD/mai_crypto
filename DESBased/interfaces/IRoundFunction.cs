
namespace DESBased.Core.Interfaces {
public interface IRoundFunction {
    byte[] Transform(byte[] inputBlock, in byte[] roundKey);
}
}
