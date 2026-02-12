using DESBased.Core.Interfaces;
using MacGuffin.Schedule;
using MacGuffin.Tables;

namespace MacGuffin {
public class MacGuffinCipher : IBlockCipher {
    private const int BLOCK_SIZE = 8;        
    private ushort[]? _roundKeys;
    // private byte[][]? _roundKeys;
    
    public int BlockSize => BLOCK_SIZE;
    
    public void Init(in byte[] key) {
        if (key is null) throw new ArgumentNullException(nameof(key), "MacGuffin key is null");
        if (key.Length != 16) throw new ArgumentException("MacGuffin key must be 16 bytes (128 bits)");
        
        // stable init
        _ = SBoxes.Stable;
        
        var keySchedule = new MacGuffinKeySchedule();
        _roundKeys = keySchedule.GenerateRoundKeys(key);
    }

    public byte[] Encrypt(in byte[] block) {
        ValidateState(block);
        return Process(block, false);
    }

    public byte[] Decrypt(in byte[] block) {
        ValidateState(block);
        return Process(block, true);
    }

    private byte[] Process(byte[] block, bool decrypt) {
        if (_roundKeys == null)  throw new InvalidOperationException("Cipher not initialized. Call Init() first.");
        
        byte[] result = new byte[BLOCK_SIZE];
        Buffer.BlockCopy(block, 0, result, 0, BLOCK_SIZE);
        
        if (decrypt) MacGuffinCore.DecryptBlock(result, _roundKeys);
        else MacGuffinCore.EncryptBlock(result, _roundKeys);

        return result;
    }

    private void ValidateState(in byte[] block) {
        if (_roundKeys is null)  throw new InvalidOperationException("Cipher not initialized. Call Init() first.");
        if (block is null) throw new ArgumentNullException(nameof(block), "The block is null.");
        if (block.Length != BlockSize) throw new ArgumentException($"The block size is not {BlockSize * 8} bits.");
    }
}
}
