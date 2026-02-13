
using System.Text;

public class RC4Tests {
    private static readonly byte[] TestKey = Encoding.UTF8.GetBytes("MySecretKey123!");

    [Fact]
    public void RC4_ThrowsOnNullKey() {
        Assert.Throws<ArgumentException>(() => new RC4(null!));
    }

    [Fact]
    public void RC4_ThrowsOnEmptyKey() {
        Assert.Throws<ArgumentException>(() => new RC4(Array.Empty<byte>()));
    }

    [Theory]
    [InlineData("Hello")]
    [InlineData("A")]
    [InlineData("")]
    [InlineData("Русский текст и emoji 😊!")]
    public void RC4_ProcessChunk_Symmetric(string input) {
        var data = Encoding.UTF8.GetBytes(input);
        var original = (byte[])data.Clone();

        var cipher = new RC4(TestKey);
        cipher.ProcessChunk(data, data.Length);

        var decipher = new RC4(TestKey);
        decipher.ProcessChunk(data, data.Length);

        Assert.Equal(original, data);
    }

    [Fact]
    public void RC4_ProcessChunk_ModifiesInPlace() {
        var data = new byte[] { 1, 2, 3, 4 };
        var original = (byte[])data.Clone();

        var cipher = new RC4(TestKey);
        cipher.ProcessChunk(data, data.Length);

        Assert.NotEqual(original, data);
    }

    [Fact]
    public void RC4_DifferentKeys_ProduceDifferentOutputs() {
        var data = Encoding.UTF8.GetBytes("test");
        var copy1 = (byte[])data.Clone();
        var copy2 = (byte[])data.Clone();

        new RC4(Encoding.UTF8.GetBytes("key1")).ProcessChunk(copy1, copy1.Length);
        new RC4(Encoding.UTF8.GetBytes("key2")).ProcessChunk(copy2, copy2.Length);

        Assert.NotEqual(copy1, copy2);
    }


    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(1024)]
    [InlineData(1024 * 1024)]
    public async Task EncryptFileAsync_Roundtrip_Success(int fileSize) {
        var inputPath = Path.GetTempFileName();
        var encryptedPath = Path.GetTempFileName();
        var decryptedPath = Path.GetTempFileName();

        try {
            var originalData = GenerateRandomBytes(fileSize);
            await File.WriteAllBytesAsync(inputPath, originalData);

            await RC4Async.EncryptFileAsync(inputPath, encryptedPath, TestKey, bufferSize: 512);
            await RC4Async.DecryptFileAsync(encryptedPath, decryptedPath, TestKey, bufferSize: 512);

            var decryptedData = await File.ReadAllBytesAsync(decryptedPath);
            Assert.Equal(originalData, decryptedData);

            if (fileSize > 0) {
                var encryptedData = await File.ReadAllBytesAsync(encryptedPath);
                Assert.NotEqual(originalData, encryptedData);
            }
        }
        finally {
            DeleteIfExists(inputPath);
            DeleteIfExists(encryptedPath);
            DeleteIfExists(decryptedPath);
        }
    }

    [Fact]
    public async Task EncryptFileAsync_SameKeyDifferentFiles_DifferentOutputs() {
        var file1 = Path.GetTempFileName();
        var file2 = Path.GetTempFileName();
        var enc1 = Path.GetTempFileName();
        var enc2 = Path.GetTempFileName();

        try {
            await File.WriteAllBytesAsync(file1, new byte[] { 1, 2, 3 });
            await File.WriteAllBytesAsync(file2, new byte[] { 4, 5, 6 });

            await RC4Async.EncryptFileAsync(file1, enc1, TestKey, 1024);
            await RC4Async.EncryptFileAsync(file2, enc2, TestKey, 1024);

            var e1 = await File.ReadAllBytesAsync(enc1);
            var e2 = await File.ReadAllBytesAsync(enc2);
            Assert.NotEqual(e1, e2);
        }
        finally {
            DeleteIfExists(file1); DeleteIfExists(file2);
            DeleteIfExists(enc1); DeleteIfExists(enc2);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(17)]
    [InlineData(512)]
    [InlineData(4096)]
    [InlineData(65536)]
    public async Task EncryptFileAsync_DifferentBufferSizes_WorkCorrectly(int bufferSize) {
        var input = Path.GetTempFileName();
        var output = Path.GetTempFileName();
        var back = Path.GetTempFileName();

        try {
            var data = GenerateRandomBytes(1000);
            await File.WriteAllBytesAsync(input, data);

            await RC4Async.EncryptFileAsync(input, output, TestKey, bufferSize);
            await RC4Async.DecryptFileAsync(output, back, TestKey, bufferSize);

            var result = await File.ReadAllBytesAsync(back);
            Assert.Equal(data, result);
        }
        finally {
            DeleteIfExists(input); DeleteIfExists(output); DeleteIfExists(back);
        }
    }

    [Fact]
    public async Task EncryptFileAsync_NullInputPath_Throws() {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            RC4Async.EncryptFileAsync(null!, "out", TestKey, 1024));
    }

    [Fact]
    public async Task EncryptFileAsync_EmptyInputPath_Throws() {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            RC4Async.EncryptFileAsync("", "out", TestKey, 1024));
    }

    [Fact]
    public async Task EncryptFileAsync_NullOutputPath_Throws() {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            RC4Async.EncryptFileAsync("in", null!, TestKey, 1024));
    }

    [Fact]
    public async Task EncryptFileAsync_BufferSizeZero_Throws() {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            RC4Async.EncryptFileAsync("in", "out", TestKey, 0));
    }

    [Fact]
    public async Task EncryptFileAsync_NonExistentFile_Throws() {
        var ex = await Assert.ThrowsAsync<FileNotFoundException>(() =>
            RC4Async.EncryptFileAsync("nonexistent.bin", "out.bin", TestKey, 1024));
    }

    [Fact]
    public async Task EncryptFileAsync_BinaryFile_Roundtrip() {
        var peHeader = new byte[] {
            0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00
        };

        var input = Path.GetTempFileName();
        var enc = Path.GetTempFileName();
        var dec = Path.GetTempFileName();

        try {
            await File.WriteAllBytesAsync(input, peHeader);
            await RC4Async.EncryptFileAsync(input, enc, TestKey, 16);
            await RC4Async.DecryptFileAsync(enc, dec, TestKey, 16);

            var result = await File.ReadAllBytesAsync(dec);
            Assert.Equal(peHeader, result);
        }
        finally {
            DeleteIfExists(input); DeleteIfExists(enc); DeleteIfExists(dec);
        }
    }

    // === 6. Тесты на текстовые файлы с разными кодировками ===

    [Theory]
    [InlineData("Hello, world!", "utf-8")]
    [InlineData("Привет, мир!", "utf-8")]
    [InlineData("مرحبا بالعالم!", "utf-8")]
    [InlineData("Hello\0World", "utf-8")] // с нулём
    public async Task EncryptFileAsync_TextFile_Roundtrip(string text, string encodingName) {
        var enc = Encoding.GetEncoding(encodingName);
        var data = enc.GetBytes(text);

        var input = Path.GetTempFileName();
        var output = Path.GetTempFileName();
        var back = Path.GetTempFileName();

        try {
            await File.WriteAllBytesAsync(input, data);
            await RC4Async.EncryptFileAsync(input, output, TestKey, 100);
            await RC4Async.DecryptFileAsync(output, back, TestKey, 100);

            var result = await File.ReadAllBytesAsync(back);
            Assert.Equal(data, result);
        }
        finally {
            DeleteIfExists(input); DeleteIfExists(output); DeleteIfExists(back);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(10)]
    public async Task StressTest_MultipleFiles(int count) {
        var inputFiles = new string[count];
        var encryptedFiles = new string[count];
        var decryptedFiles = new string[count];

        for (int i = 0; i < count; i++) {
            inputFiles[i] = Path.GetTempFileName();
            encryptedFiles[i] = Path.GetTempFileName();
            decryptedFiles[i] = Path.GetTempFileName();

            var data = GenerateRandomBytes(100_000);
            await File.WriteAllBytesAsync(inputFiles[i], data);
        }

        try {
            for (int i = 0; i < count; i++) {
                await RC4Async.EncryptFileAsync(inputFiles[i], encryptedFiles[i], TestKey, 4096);
                await RC4Async.DecryptFileAsync(encryptedFiles[i], decryptedFiles[i], TestKey, 4096);

                var original = await File.ReadAllBytesAsync(inputFiles[i]);
                var result = await File.ReadAllBytesAsync(decryptedFiles[i]);
                Assert.Equal(original, result);
            }
        }
        finally {
            foreach (var file in inputFiles) DeleteIfExists(file);
            foreach (var file in encryptedFiles) DeleteIfExists(file);
            foreach (var file in decryptedFiles) DeleteIfExists(file);
        }
    }

    [Fact]
    public void RC4_StatePreservedBetweenChunks() {
        var fullData = GenerateRandomBytes(1000);
        var chunk1 = fullData.Take(400).ToArray();
        var chunk2 = fullData.Skip(400).Take(600).ToArray();

        var cipher = new RC4(TestKey);
        cipher.ProcessChunk(chunk1, chunk1.Length);
        cipher.ProcessChunk(chunk2, chunk2.Length);
        var encryptedParts = chunk1.Concat(chunk2).ToArray();

        var fullCopy = (byte[])fullData.Clone();
        new RC4(TestKey).ProcessChunk(fullCopy, fullCopy.Length);

        Assert.Equal(fullCopy, encryptedParts);
    }


    private static byte[] GenerateRandomBytes(int size) {
        if (size == 0) return Array.Empty<byte>();
        var random = new Random(42); // deterministic for tests
        var data = new byte[size];
        random.NextBytes(data);
        return data;
    }

    private static void DeleteIfExists(string path) {
        if (File.Exists(path)) File.Delete(path);
    }
}