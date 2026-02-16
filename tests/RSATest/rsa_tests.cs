using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Numerics;
using Xunit;
using RSA;
using static RSA.RSA;

namespace RSATests
{
    public class RsaTests : IDisposable
    {
        private readonly string _testDir;

        public RsaTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "RsaTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);
        }

        public void Dispose()
        {
            if (Directory.Exists(_testDir))
                Directory.Delete(_testDir, true);
        }

        private string GetTestFilePath(string name) => Path.Combine(_testDir, name);

        private byte[] GenerateRandomBytes(int length)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        private async Task<(string original, string encrypted, string decrypted)> CreateTestFiles(byte[] data)
        {
            var original = GetTestFilePath("original.bin");
            var encrypted = GetTestFilePath("encrypted.rsa");
            var decrypted = GetTestFilePath("decrypted.bin");

            await File.WriteAllBytesAsync(original, data);
            return (original, encrypted, decrypted);
        }

        public static TheoryData<RSA.RSA.PrimalityTest, int> KeyGenBasicCases => new()
        {
            { RSA.RSA.PrimalityTest.Fermat, 512 },
            { RSA.RSA.PrimalityTest.MillerRabin, 1024 },
            { RSA.RSA.PrimalityTest.SolovayStrassen, 512 }
        };

        [Theory]
        [MemberData(nameof(KeyGenBasicCases))]
        public void KeyGenerator_GeneratesValidKeyPair(RSA.RSA.PrimalityTest test, int bits)
        {
            var kg = new RSA.RSA.KeyGenerator(test, bits, 5);
            var (n, e, d) = kg.GenerateKeyPair();
            Assert.True(n > 0 && e > 0 && d > 0);
            Assert.InRange(n.GetBitLength(), bits - 7, bits);
        }

        [Fact]
        public void GeneratedKeys_Satisfy_RSA_Equation_1024()
        {
            var kg = new RSA.RSA.KeyGenerator(RSA.RSA.PrimalityTest.MillerRabin, 1024, 5);
            var (n, e, d) = kg.GenerateKeyPair();

            var msg = BigInteger.Abs(new BigInteger(GenerateRandomBytes(128)));
            if (msg >= n) msg %= n;
            if (msg == 0) msg = 1;

            var cipher = BigInteger.ModPow(msg, e, n);
            var plain = BigInteger.ModPow(cipher, d, n);
            Assert.Equal(msg, plain);
        }

        [Fact]
        public void GeneratedKeys_AreResistantToWienerAttack_512()
        {
            var kg = new RSA.RSA.KeyGenerator(RSA.RSA.PrimalityTest.MillerRabin, 512, 5);
            var (n, e, _) = kg.GenerateKeyPair();
            Assert.Null(RSA.WienerAttack.MakeWienerAttack(n, e));
        }

        [Fact]
        public void MakeWienerAttack_WithSmallD_ReturnsExpectedDAndPhi() {
            BigInteger n = 3127; // 53*59
            BigInteger e = 2011; // e * d ≡ 1 mod phi(n); d = 3
            BigInteger expectedD = 3;
            BigInteger expectedPhi = 3016;

            WienerAttackResult? result = WienerAttack.MakeWienerAttack(n, e);

            Assert.NotNull(result);
            Assert.Equal(expectedD, result!.D);
            Assert.Equal(expectedPhi, result.Phi);
            Assert.NotEmpty(result.Convergents);
            Assert.Contains(result.Convergents, c => c.Denominator == expectedD);
        }


        [Fact]
        public void KeyGenerator_ThrowsOnInvalidSizes()
        {
            Assert.Throws<ArgumentException>(() => new RSA.RSA.KeyGenerator(RSA.RSA.PrimalityTest.MillerRabin, 255, 5));
            Assert.Throws<ArgumentException>(() => new RSA.RSA.KeyGenerator(RSA.RSA.PrimalityTest.MillerRabin, 0, 5));
            Assert.Throws<ArgumentException>(() => new RSA.RSA.KeyGenerator(RSA.RSA.PrimalityTest.MillerRabin, -100, 5));
        }

        [Fact]
        public async Task KeyGenerator_CanGenerateKeysInParallel()
        {
            var tasks = Enumerable.Range(0, 5).Select(_ =>
                Task.Run(() =>
                {
                    var kg = new RSA.RSA.KeyGenerator(RSA.RSA.PrimalityTest.MillerRabin, 512, 5);
                    var (n, _, _) = kg.GenerateKeyPair();
                    Assert.True(n > 0);
                })).ToArray();

            await Task.WhenAll(tasks);
        }

        public static TheoryData<byte[]> SmallFileContent => new()
        {
            new byte[0],
            new byte[] { 1 },
            new byte[] { 1, 2, 3, 4, 5 },
            GenerateRandomBytesStatic(100),
            GenerateRandomBytesStatic(1000),
        };

        private static byte[] GenerateRandomBytesStatic(int length)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        [Theory]
        [MemberData(nameof(SmallFileContent))]
        public async Task EncryptDecrypt_RoundTrip_1024(byte[] data)
        {
            var rsa = new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, 0.99, 1024);

            var (orig, enc, dec) = await CreateTestFiles(data);
            await rsa.EncryptFileAsync(orig, enc, 1024);
            await rsa.DecryptFileAsync(enc, dec);

            var result = await File.ReadAllBytesAsync(dec);
            Assert.Equal(data, result);
        }

        public static TheoryData<int> ReasonableBufferSizes => new()
        {
            256, 1024, 4096
        };

        [Theory]
        [MemberData(nameof(ReasonableBufferSizes))]
        public async Task EncryptDecrypt_BufferSizeVariants(int bufferSize)
        {
            var data = GenerateRandomBytes(5000);
            var rsa = new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, 0.99, 1024);

            var (orig, enc, dec) = await CreateTestFiles(data);
            await rsa.EncryptFileAsync(orig, enc, bufferSize);
            await rsa.DecryptFileAsync(enc, dec);

            var result = await File.ReadAllBytesAsync(dec);
            Assert.Equal(data, result);
        }

        [Fact]
        public async Task DecryptFile_ThrowsOnInvalidHeader()
        {
            var fakeEnc = GetTestFilePath("fake.rsa");
            await File.WriteAllBytesAsync(fakeEnc, new byte[7]);

            var rsa = new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, 0.99, 512);

            var dec = GetTestFilePath("dec.bin");
            await Assert.ThrowsAsync<CryptographicException>(() => rsa.DecryptFileAsync(fakeEnc, dec));
        }

        [Fact]
        public void Padding_IsAppliedCorrectly()
        {
            var rsa = new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, 0.99, 512);

            var data = new byte[] { 1, 2, 3 };
            var method = typeof(RSA.RSA).GetMethod("GeneratePadding",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                ?? throw new InvalidOperationException("Method GeneratePadding not found");

            var del = (Func<Span<byte>, byte[]>)Delegate.CreateDelegate(
                typeof(Func<Span<byte>, byte[]>), rsa, method);

            var padded = del(data);
            var blockBytes = (int)typeof(RSA.RSA).GetField("_blockBytes",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
                .GetValue(rsa)!;

            Assert.Equal(blockBytes, padded.Length);
            Assert.Equal((byte)0x00, padded[0]);
            Assert.Equal((byte)0x02, padded[1]);

            var paddingEnd = blockBytes - data.Length - 1;
            Assert.Equal((byte)0x00, padded[paddingEnd]);
            for (int i = 0; i < data.Length; i++)
                Assert.Equal(data[i], padded[blockBytes - data.Length + i]);
        }

        [Fact]
        public async Task EncryptDecrypt_EmptyAndSingleByte()
        {
            foreach (var data in new[] { new byte[0], new byte[] { 0xFF } })
            {
                var rsa = new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, 0.99, 512);

                var (orig, enc, dec) = await CreateTestFiles(data);
                await rsa.EncryptFileAsync(orig, enc, 256);
                await rsa.DecryptFileAsync(enc, dec);

                var result = await File.ReadAllBytesAsync(dec);
                Assert.Equal(data, result);
            }
        }

        [Fact]
        public void RSA_Constructor_ThrowsOnInvalidConfidence()
        {
            Assert.Throws<ArgumentException>(() => new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, -0.1, 1024));
            Assert.Throws<ArgumentException>(() => new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, 1.0, 1024));
            Assert.Throws<ArgumentException>(() => new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, 1.5, 1024));
        }

        [Fact]
        public void RSA_Constructor_ThrowsOnSmallKeySize()
        {
            Assert.Throws<ArgumentException>(() => new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, 0.99, 255));
            Assert.Throws<ArgumentException>(() => new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, 0.99, 0));
        }

        [Fact]
        public void GenerateNewKeyPair_RegeneratesValidKeys()
        {
            var rsa = new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, 0.99, 512);
            
            var n1 = (BigInteger)typeof(RSA.RSA).GetField("_n", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(rsa)!;
            
            rsa.GenerateNewKeyPair();
            
            var n2 = (BigInteger)typeof(RSA.RSA).GetField("_n", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(rsa)!;
            
            Assert.NotEqual(n1, n2);
            Assert.True(n2 > 0);
        }

        [Theory]
        [InlineData(0.5, 1)]
        [InlineData(0.75, 1)]
        [InlineData(0.9375, 2)]      
        [InlineData(0.984375, 3)]  
        [InlineData(0.99609375, 4)] 
        [InlineData(0.999, 5)]
        public void Confidence_CalculatesCorrectIterations(double confidence, int expectedIterations)
        {
            var rsa = new RSA.RSA(RSA.RSA.PrimalityTest.MillerRabin, confidence, 512);
            
            var kgField = typeof(RSA.RSA).GetField("_keyGenerator", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var kg = (RSA.RSA.KeyGenerator)kgField!.GetValue(rsa)!;

            var iterationsField = typeof(RSA.RSA.KeyGenerator).GetField("_iterations", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var actualIterations = (int)iterationsField!.GetValue(kg)!;
            
            Assert.Equal(expectedIterations, actualIterations);
        }
    }
}