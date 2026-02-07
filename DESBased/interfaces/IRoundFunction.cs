
namespace DESBased.Core.Interfaces {
public interface IRoundFunction {
    byte[] Transform(in byte[] inputBlock, in byte[] roundKey);
}
}
