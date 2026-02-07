
using DESBased.Core.Context;
using DESBased.Core.Ciphers.DES;
using DESBased.Core.Ciphers.TripleDES;
using DESBased.Core.Ciphers.DEAL;
using DESBased.Core.Modes;
using DESBased.Core.Padding;
using DESBased.Core.Interfaces;
using System.Reflection;

namespace DESBased.Core.Tests {
public class FinalTest {
    // Checks fewer encryption options for media files
    private static readonly bool SIMPLE_TEST = true;
    // exe file is located in bin/Debug/netX.X/DESBasedTests.dll
    private static readonly string ProjectDirectory =
    Path.GetDirectoryName(
        Path.GetDirectoryName(
            Path.GetDirectoryName(
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
            )
        )
    )!;

    private static readonly string TestDataPath = Path.Combine(
        ProjectDirectory, "test_data"
    );

    private static readonly string TestResultPath = Path.Combine(
        ProjectDirectory, "test_result"
    );

    [Theory]
    [MemberData(nameof(GetTestData))]
    public async Task RoundTrip_EncryptDecrypt_MultipleBlock(
        IBlockCipher cipher, int keySize,  MyCipherMode mode, MyPadding padding, byte[] text
    ) {
        byte[] key = GenerateByteString(keySize);
        if (cipher is DESCipher or TripleDESCipher) key = FixKeyParity(key);
        byte[] iv = GenerateByteString(cipher.BlockSize);
        int blockSize = cipher.BlockSize;
        if (padding == MyPadding.Zeros && text.Length > 0) text[^1] |= 1;

        object[] args = mode == MyCipherMode.RD ? [ cipher, Guid.NewGuid().GetHashCode() ] : [cipher];

        // CipherContext stores the cipher state ONLY for encryption OR decryption.
        // Using the same context for both encryption AND decryption results in ~pseudorandom~ behavior.
        var contextEnc = new CipherContext(key, mode, padding, iv, args);
        var contextDec = new CipherContext(key, mode, padding, iv, args);

        byte[] ct = await contextEnc.EncryptAsync(text);
        byte[] rt = await contextDec.DecryptAsync(ct);
        
        Assert.Equal(text, rt);
    }
    
    [Theory]
    [MemberData(nameof(GetFileTestData))]
    public async Task File_EncryptDecrypt_RoundTrip(IBlockCipher cipher, int keySize,
        MyCipherMode mode, MyPadding padding, string testFileName
    ) {
        byte[] key = GenerateByteString(keySize);
        if (cipher is DESCipher or TripleDESCipher) key = FixKeyParity(key);
        byte[] iv = GenerateByteString(cipher.BlockSize);

        object[] args = mode == MyCipherMode.RD ? [ cipher, Guid.NewGuid().GetHashCode() ] : [cipher];

        string inputPath = Path.Combine(TestDataPath, testFileName);
        string fileExt = Path.GetExtension(inputPath)[1..];
        // output file names
        string cipherName = cipher.GetType().Name.Replace("Cipher", "");
        var encFileName = $"enc_{Path.GetFileNameWithoutExtension(testFileName)}_{cipherName}_{keySize}_{mode}_{padding}{Path.GetExtension(testFileName)}";
        var decFileName = $"dec_{Path.GetFileNameWithoutExtension(testFileName)}_{cipherName}_{keySize}_{mode}_{padding}{Path.GetExtension(testFileName)}";
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
            // Excludes dot
            Directory.CreateDirectory(Path.Combine(TestResultPath, fileExt[1..])); 
        }
    }
    
    public static IEnumerable<object[]> GetCipherModePaddingCombinations(bool isMediaFile = false) {
        object[][] ciphers = [
            [new DESCipher(), 8],  // DES: 8 byte key
            [ new TripleDESCipher(), 16 ],  // 3DES: 16 (EDE2)
            [ new TripleDESCipher(), 24 ],  // 3DES: 24 (EDE3)
            [ new DEALCipher(128), 16 ],  // DEAL-128:16
            [ new DEALCipher(192), 24 ],  // DEAL-192: 24
            [ new DEALCipher(256), 32 ]  // DEAL-256: 32
        ];

        MyCipherMode[] modes = Enum.GetValues<MyCipherMode>();
        MyPadding[] allPaddings = Enum.GetValues<MyPadding>();

        foreach (var cipherInfo in ciphers) {
            var cipher = (IBlockCipher)cipherInfo[0];
            int keySize = (int)cipherInfo[1];

            foreach (var mode in modes) {
                MyPadding[] paddings = [];
                if (isMediaFile && cipher is DEALCipher or TripleDESCipher) {
                    if (mode is MyCipherMode.ECB) paddings = [ MyPadding.Iso10126, MyPadding.Pkcs7 ];
                    else if (mode is MyCipherMode.CTR) paddings = [ MyPadding.Iso10126 ];
                    else continue;
                }
                else {
                    if (mode is MyCipherMode.OFB or MyCipherMode.CTR or MyCipherMode.RD)
                        paddings = [MyPadding.Iso10126];
                    else paddings = allPaddings;
                }
                foreach (var padding in paddings) yield return [ cipher, keySize, mode, padding ];
            }
        }
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
            int blockSize = combo[0] switch {
                DESCipher => 8,
                TripleDESCipher => 8,
                DEALCipher => 16,
                _ => throw new ArgumentException()
            };
            byte[][] data = [
                GenerateByteString(blockSize * 4),
                GenerateByteString(blockSize * 3 + 5),
                GenerateByteString(blockSize * 400 + 5),
                GenerateByteString(blockSize * 500),
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
    
    private static byte[] FixKeyParity(byte[] keyPart) {
        for (int i = 0; i < keyPart.Length; i++) {
            bool parity = true;
            for (int j = 0; j < 8; j++) parity ^= (keyPart[i] & (1 << (7 - j))) != 0;
            if (parity) keyPart[i] ^= 0x01;
        }
        return keyPart;
    }
}
}
