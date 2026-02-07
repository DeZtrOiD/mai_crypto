
namespace DESBased.Core.Interfaces {
public interface IKeySchedule {
    byte[][] GenerateRoundKeys(in byte[] key);
}
}
