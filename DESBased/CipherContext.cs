// #=#=#=#=#=#=#=#=#=#=#=#=#-DeZtrOidDeV-#=#=#=#=#=#=#=#=#=#=#=#=#
// Author: DeZtrOid
// Date: 2025
// Desc: CipherContext stores the cipher state
// ONLY for encryption OR decryption
// 
// Using the same context for BOTH encryption AND decryption
// results in ~pseudorandom~ behavior.
// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

using DESBased.Core.Modes;
using DESBased.Core.Interfaces;
using DESBased.Core.Padding;
using System.Buffers;

namespace DESBased.Core.Context {
public class CipherContext {
    private readonly IBlockCipher _cipher;
    private readonly ICipherMode _modeImpl;
    private readonly MyPadding _padding;
    private readonly int _bufferSize = 1024 * 16;

    public CipherContext(in byte[] key, MyCipherMode mode, MyPadding padding,
        in byte[] iv, params object[] args
    ) {
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (args is null) throw new ArgumentNullException(
            $"Constructor requires at least one argument in 'args': IBlockCipher implementation."
        );
        if (args.Length == 0) throw new ArgumentException(
            $"Constructor requires at least one argument in 'args': IBlockCipher implementation."
        );
        _cipher = args[0] as IBlockCipher 
            ?? throw new ArgumentException(
                $"First argument in 'args' must be an IBlockCipher implementation, but was {args[0]?.GetType().Name ?? "null"}."
        );
        object[] additionalArgs = args.Length > 1 ? args[1..] : Array.Empty<object>();

        _modeImpl = CipherModeFactory.Create( mode );
        _padding = padding;

        _cipher.Init(key ?? throw new ArgumentNullException(nameof(key)));
        _modeImpl.Init(_cipher, iv, additionalArgs);
    }

    public async Task<byte[]> EncryptAsync(byte[] plaintext) {
        if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));

        return await Task.Run(() => {
            byte[] processed = _modeImpl.RequiresPadding
                ? PaddingProvider.Apply(plaintext, _cipher.BlockSize, _padding)
                : plaintext;

            return _modeImpl.Encrypt(processed);
        });
    }

    public async Task<byte[]> DecryptAsync(byte[] ciphertext) {
        if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));

        return await Task.Run(() => {
            byte[] processed = _modeImpl.Decrypt(ciphertext);

            return _modeImpl.RequiresPadding
                ? PaddingProvider.Remove(processed, _padding)
                : processed;
        });
    }

    public async Task EncryptFileAsync(string inputPath, string outputPath) {
        ValidateFiles(inputPath, outputPath, inputPath);

        int blockSize = _cipher.BlockSize;
        int bufferSize = _bufferSize - (_bufferSize % blockSize);
        
        using var inStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, useAsync: true);
        using var outStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize, useAsync: true);
        
        if (_modeImpl.RequiresPadding)
            await ProcessFileWithPaddingAsync(inStream, outStream, blockSize, bufferSize, isEncrypt: true);
        else
            await ProcessFileWithoutPaddingAsync(inStream, outStream, bufferSize, isEncrypt: true);
    }

    public async Task DecryptFileAsync(string inputPath, string outputPath) {
        ValidateFiles(inputPath, outputPath, inputPath);

        int blockSize = _cipher.BlockSize;
        int bufferSize = _bufferSize - (_bufferSize % blockSize);
        
        using var inStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, useAsync: true);
        using var outStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize, useAsync: true);
    
        if (_modeImpl.RequiresPadding)
            await ProcessFileWithPaddingAsync(inStream, outStream, blockSize, bufferSize, isEncrypt: false);
        else
            await ProcessFileWithoutPaddingAsync(inStream, outStream, bufferSize, isEncrypt: false);
    }


    private async Task ProcessFileWithoutPaddingAsync(
        FileStream inStream, FileStream outStream, int bufferSize, bool isEncrypt
    ) {
        byte[] buffer = new byte[_bufferSize];
        int readBytes;
        while ((readBytes = await inStream.ReadAsync(buffer, 0, bufferSize)) > 0) {
            byte[] block = buffer.AsMemory(0, readBytes).ToArray();
            byte[] processed = await (isEncrypt ? EncryptAsync(block) : DecryptAsync(block));

            await outStream.WriteAsync(processed, 0, processed.Length);
        }
    }

    private async Task ProcessFileWithPaddingAsync(
        FileStream inStream, FileStream outStream, int blockSize, int bufferSize, bool isEncrypt
    ){
        byte[] buffer = new byte[_bufferSize];
        long totalBytes = inStream.Length;
        long bytesRead = 0;
        int readBytes;
        
        while ((readBytes = await inStream.ReadAsync(buffer, 0, bufferSize)) > 0) {
            bytesRead += readBytes;
            bool isLastBlock = bytesRead == totalBytes;
            byte[] block = buffer.AsMemory(0, readBytes).ToArray();

            if (isLastBlock && isEncrypt) block = PaddingProvider.Apply(block, blockSize, _padding);
            byte[] processed = isEncrypt ? _modeImpl.Encrypt(block) : _modeImpl.Decrypt(block);
            if (isLastBlock && !isEncrypt) processed = PaddingProvider.Remove(processed, _padding);

            await outStream.WriteAsync(processed, 0, processed.Length);
        }
    }

    private static void ValidateFiles(in string inputPath, in string outputPath, in string path) {
        if (string.IsNullOrWhiteSpace(inputPath)) throw new ArgumentException("Input path cannot be null or empty.");
        if (string.IsNullOrWhiteSpace(outputPath)) throw new ArgumentException("Output path cannot be null or empty.");
        if (!File.Exists(path)) throw new ArgumentException($"File: {path} doesn't exist");
    }
}
}
