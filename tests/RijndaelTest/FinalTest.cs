
#pragma warning disable CS8604

using DESBased.Core.Context;
using DESBased.Core.Modes;
using DESBased.Core.Padding;
using DESBased.Core.Interfaces;
using System.Reflection;

namespace Rijndael.Tests  {
public class FinalTest  {
    private static readonly bool SIMPLE_TEST = true;
    private static readonly bool OFF_FILE_TEST = true;
    private static readonly string ProjectDirectory =
    Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(
        Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
    )))!;

    private static readonly string TestDataPath = Path.Combine(
        Path.GetDirectoryName(ProjectDirectory), "test_data"
    );

    private static readonly string TestResultPath = Path.Combine(
        ProjectDirectory, "test_result"
    );

    [Theory]
    [MemberData(nameof(GetTestData))]
    public async Task RoundTripEncryptDecryptMultipleBlock(
        IBlockCipher cipher, int keySize, MyCipherMode mode, MyPadding padding, byte[] text
    ) {
        byte[] key = GenerateByteString(keySize);
        byte[] iv = GenerateByteString(cipher.BlockSize);
        if (padding == MyPadding.Zeros && text.Length > 0) text[^1] |= 1;
        object[] args = mode == MyCipherMode.RD ? [cipher, Guid.NewGuid().GetHashCode()] : [cipher];
        var contextEnc = new CipherContext(key, mode, padding, iv, args);
        var contextDec = new CipherContext(key, mode, padding, iv, args);

        byte[] ct = await contextEnc.EncryptAsync(text);
        Assert.Equal(text, await contextDec.DecryptAsync(ct));
    }

    [Theory]
    [MemberData(nameof(GetFileTestData))]
    public async Task FileEncryptDecryptRoundTrip(IBlockCipher cipher, int keySize,
        MyCipherMode mode, MyPadding padding, string testFileName
    ) {
        if (OFF_FILE_TEST) return;
        byte[] key = GenerateByteString(keySize);
        byte[] iv = GenerateByteString(cipher.BlockSize);

        object[] args = mode == MyCipherMode.RD ? [cipher, Guid.NewGuid().GetHashCode()] : [cipher];

        string inputPath = Path.Combine(TestDataPath, testFileName);
        string fileExt = Path.GetExtension(inputPath)[1..];
        string cipherName = cipher.GetType().Name.Replace("Cipher", "");

        string encFileName = $"enc_{Path.GetFileNameWithoutExtension(testFileName)}_{cipherName}_{keySize}_{cipher.BlockSize}_{mode}_{padding}{Path.GetExtension(testFileName)}";
        string decFileName = $"dec_{Path.GetFileNameWithoutExtension(testFileName)}_{cipherName}_{keySize}_{cipher.BlockSize}_{mode}_{padding}{Path.GetExtension(testFileName)}";

        string encPath = Path.Combine(TestResultPath, fileExt, encFileName);
        string decPath = Path.Combine(TestResultPath, fileExt, decFileName);

        if (File.Exists(encPath)) File.Delete(encPath);
        if (File.Exists(decPath)) File.Delete(decPath);

        var encContext = new CipherContext(key, mode, padding, iv, args);
        await encContext.EncryptFileAsync(inputPath, encPath);

        var decContext = new CipherContext(key, mode, padding, iv, args);
        await decContext.DecryptFileAsync(encPath, decPath);

        byte[] originalBytes = await File.ReadAllBytesAsync(inputPath);
        byte[] encryptedBytes = await File.ReadAllBytesAsync(encPath);
        byte[] decryptedBytes = await File.ReadAllBytesAsync(decPath);

        Assert.Equal(originalBytes, decryptedBytes);
        Assert.NotEqual(originalBytes, encryptedBytes);
    }

    static FinalTest() {
        Directory.CreateDirectory(TestDataPath);
        Directory.CreateDirectory(TestResultPath);
        string[] files = Directory.GetFiles(TestDataPath);
        foreach (var file in files) {
            string fileExt = Path.GetExtension(file);
            Directory.CreateDirectory(Path.Combine(TestResultPath, fileExt[1..]));
        }
    }

    public static IEnumerable<object[]> GetCipherModePaddingCombinations(bool isMediaFile = false) {

        MyCipherMode[] modes = Enum.GetValues<MyCipherMode>();
        MyPadding[] allPaddings = Enum.GetValues<MyPadding>();

        byte gfMod = 0x1B;
        foreach (int blockSizeBits in new[] { 128, 192, 256 }) {
            foreach (int keySizeBits in new[] { 128, 192, 256 }) {
                var cipher = new RijndaelBlockCipher((ushort)blockSizeBits, (ushort)keySizeBits, gfMod);
                int keySizeBytes = keySizeBits / 8;

                foreach (var mode in modes) {
                    MyPadding[] paddings = GetPaddingsForCipherMode(cipher, mode, isMediaFile, allPaddings);
                    foreach (var padding in paddings)
                        yield return [cipher, keySizeBytes, mode, padding];
                }
            }
        }
    }

    private static MyPadding[] GetPaddingsForCipherMode(
        IBlockCipher cipher, MyCipherMode mode, bool isMediaFile, MyPadding[] allPaddings
    ) {
        if (isMediaFile && (cipher is RijndaelBlockCipher)) {
            if (mode == MyCipherMode.ECB) return [MyPadding.Iso10126, MyPadding.Pkcs7];
            if (mode == MyCipherMode.CTR) return [MyPadding.Iso10126];
            return [];
        }
        if (mode is MyCipherMode.OFB or MyCipherMode.CTR or MyCipherMode.RD)
            return [MyPadding.Iso10126];
        return allPaddings;
    }

    public static IEnumerable<object[]> GetFileTestData() {
        string[] files = Directory.GetFiles(TestDataPath);
        if (files is null || files.Length == 0) yield break;

        foreach (var file in files) {
            var fileName = Path.GetFileName(file);
            var extension = Path.GetExtension(fileName).ToLowerInvariant();
            bool isMediaFile = extension != ".txt";
            isMediaFile &= SIMPLE_TEST;

            foreach (var combo in GetCipherModePaddingCombinations(isMediaFile)) {
                var data = new object[combo.Length + 1];
                combo.CopyTo(data, 0);
                data[^1] = Path.GetFileName(file);
                yield return data;
            }
        }
    }

    public static IEnumerable<object[]> GetTestData() {
        foreach (var combo in GetCipherModePaddingCombinations()) {
            int blockSize = ((IBlockCipher)combo[0]).BlockSize;

            byte[][] data = [
                GenerateByteString(blockSize * 1),
                GenerateByteString(blockSize * 4),
                GenerateByteString(blockSize * 3 + 5),
                GenerateByteString(blockSize * 40 + 5),
                GenerateByteString(blockSize * 50),
                Array.Empty<byte>()
            ];

            foreach (byte[] text in data) {
                var result = new object[combo.Length + 1];
                combo.CopyTo(result, 0);
                result[^1] = text;
                yield return result;
            }
        }
    }

    private static byte[] GenerateByteString(int size) {
        if (size <= 0) return [];
        var rnd = new Random(Guid.NewGuid().GetHashCode());
        var key = new byte[size];
        rnd.NextBytes(key);
        return key;
    }
}
}
