
#pragma warning disable CS8625
#pragma warning disable CS8604

using DESBased.Core.Ciphers.DES;
using DESBased.Core.Modes;
using DESBased.Core.Padding;
using DESBased.Core.Utils;

namespace DESBased.Core.Context.Tests {
public class CipherContextTests {

    [Theory]
    [MemberData(nameof(TestData))]
    public async Task RoundTrip(MyCipherMode mode, MyPadding padding, int len) {
        var key = GenKey(8);
        var iv = (mode == MyCipherMode.ECB) ? null : GenerateValidIv();
        var pt = GenerateTestData(len);
        var cipher = new DESCipher();

        if (padding is MyPadding.Zeros && pt.Length != 0) pt[^1] |= 1;

        object[] args = mode == MyCipherMode.RD ? [ cipher, Guid.NewGuid().GetHashCode() ] : [cipher];

        var ct = await new CipherContext(key, mode, padding, iv, args).EncryptAsync(pt);
        Assert.Equal(pt, await new CipherContext(key, mode, padding, iv, args).DecryptAsync(ct));

        if (len == 0) return;
        var pt2 = (byte[])pt.Clone();
        pt2[0] ^= 0x10;
        Assert.NotEqual(
            await new CipherContext(key, mode, padding, iv, cipher).EncryptAsync(pt),
            await new CipherContext(key, mode, padding, iv, cipher).EncryptAsync(pt2)
        );
    }


    [Theory]
    [MemberData(nameof(StreamingTestData))]
    public async Task StreamingRoundTripWithChunking(MyCipherMode mode, MyPadding padding) {
        var key = GenKey(8);
        var iv  = GenerateValidIv();
        var pt  = GenerateTestData(317);
        var cipher = new DESCipher();
        if (padding is MyPadding.Zeros && pt is not null && pt.Length != 0) {
            pt[^1] |= 1;// avoid zero-padding ambiguity
        }

        object[] args = mode == MyCipherMode.RD ? [ cipher, Guid.NewGuid().GetHashCode() ] : [cipher];
    
        var encCtx = new CipherContext(key, mode, padding, iv, args);
        var decCtx = new CipherContext(key, mode, padding, iv, args);

        var ct = await encCtx.EncryptAsync(pt);
        encCtx = new CipherContext(key, mode, padding, iv, args);

        var chunks = new[] { 0, 1, 8, 8, 1, 0, 7, 9, 23, 100, Math.Max(pt.Length, ct.Length) };

        var encChunks = new List<byte[]>();
        var decChunks = new List<byte[]>();

        int offset = 0;
        int offsetDec = 0;
        bool RDWithDeltaDec = false;
        foreach (var sz in chunks) {
            if (offset < pt.Length) {
                var len = Math.Min(sz, pt.Length - offset);
                var tmp = await encCtx.EncryptAsync(pt.AsSpan(offset, len).ToArray());
                encChunks.Add(tmp);
                offset += len;
            }
            if (offsetDec < ct.Length) {
                if (mode is MyCipherMode.RD && !RDWithDeltaDec && sz < 8) continue;
                else RDWithDeltaDec = true;

                var len = Math.Min(sz, ct.Length - offsetDec);
                var tmp = await decCtx.DecryptAsync(ct.AsSpan(offsetDec, len).ToArray());
                decChunks.Add(tmp);
                offsetDec += len;
            }
        }
        var tmp2 = ByteUtils.Concat(encChunks.ToArray());
        Assert.NotEmpty(tmp2);
        var rt = await new CipherContext(key, mode, padding, iv, args).DecryptAsync(tmp2);
        Assert.Equal(pt, rt);

        Assert.Equal(pt, ByteUtils.Concat(decChunks.ToArray()));
    }


    [Fact]
    public async Task RandomDeltaWithDifferentSeedsProducesDifferentCiphertext() {
        var key = GenKey(8);
        var iv = GenerateValidIv();
        var plaintext = GenerateTestData(100);
        var cipher = new DESCipher();

        var ctx1 = new CipherContext(key, MyCipherMode.RD, MyPadding.Pkcs7, iv, cipher, 1001);
        var ctx2 = new CipherContext(key, MyCipherMode.RD, MyPadding.Pkcs7, iv, cipher, 2002);

        var e1 = await ctx1.EncryptAsync(plaintext);
        var e2 = await ctx2.EncryptAsync(plaintext);

        Assert.NotEqual(e1, e2);

        var d1 = new CipherContext(key, MyCipherMode.RD, MyPadding.Pkcs7, iv, cipher, 1001);
        var d2 = new CipherContext(key, MyCipherMode.RD, MyPadding.Pkcs7, iv, cipher, 2002);

        var r1 = await d1.DecryptAsync(e1);
        var r2 = await d2.DecryptAsync(e2);

        Assert.Equal(plaintext, r1);
        Assert.Equal(plaintext, r2);
    }

    [Theory]
    [MemberData(nameof(NullTestData))]
    public void ShouldThrow(byte[]? key, MyCipherMode mode, MyPadding padding, byte[] iv, params object[]? args) {
        if (mode is MyCipherMode.ECB && iv is null) return;
        Assert.Throws<ArgumentNullException>(() => new CipherContext(key, mode, padding, iv, args));
    }

    [Theory]
    [MemberData(nameof(StreamingTestData))]
    public void InvalidIvSizeShouldThrow(MyCipherMode mode, MyPadding padding) {
        Assert.Throws<ArgumentException>(() => new CipherContext(
            GenKey(8), mode, padding, new byte[7], new DESCipher()
        ));
        Assert.Throws<ArgumentException>(() => new CipherContext(
            GenKey(8), mode, padding, new byte[9], new DESCipher()
        ));
    }

    [Theory]
    [MemberData(nameof(NullFileTestData))]
    public async Task ShouldThrowFile(MyCipherMode mode, MyPadding padding, string inputPath, string outputPath) {
        var key = GenKey(8);
        var iv = (mode == MyCipherMode.ECB) ? null : GenerateValidIv();
        var cipher = new DESCipher();
        object[] args = mode == MyCipherMode.RD ? [ cipher, Guid.NewGuid().GetHashCode() ] : [cipher];
        var CC = new CipherContext(key, mode, padding, iv, args);
        
        await Assert.ThrowsAsync<ArgumentException>(() => CC.DecryptFileAsync(inputPath, outputPath));
        await Assert.ThrowsAsync<ArgumentException>(() => CC.EncryptFileAsync(inputPath, outputPath));
    }

    private static byte[] GenKey(int keySize) {
        byte[] keyPart = new byte[keySize];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(keyPart);
        byte[] result = (byte[])keyPart.Clone();
        for (int i = 0; i < result.Length; i++) {
            bool parity = true;
            for (int j = 0; j < 8; j++) parity ^= (result[i] & (1 << (7 - j))) != 0;
            if (parity) result[i] ^= 0x01;
        }
        return result;
    }

    private static byte[] GenerateValidIv(int length = 8) {
        byte[] iv = new byte[length];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(iv);
        return iv;
    }

    private static byte[] GenerateTestData(int length) {
        byte[] data = new byte[length];
        new Random(Guid.NewGuid().GetHashCode()).NextBytes(data);
        return data;
    }

    public static IEnumerable<object[]> TestData() {
        var modes = Enum.GetValues<MyCipherMode>();
        var paddings = Enum.GetValues<MyPadding>();
        int[] lengths = [ 0, 1, 7, 8, 9, 15, 17, 100 ];

        foreach (var mode in modes) {
            foreach (var padding in paddings) {
                foreach (var len in lengths) yield return new object[] { mode, padding, len };
                if (mode is MyCipherMode.OFB or MyCipherMode.CTR or MyCipherMode.RD) break;
            }                
        }
    }

    public static IEnumerable<object[]> StreamingTestData() {
        MyCipherMode[] modes = {MyCipherMode.OFB, MyCipherMode.CTR, MyCipherMode.RD};
        foreach (var mode in modes) yield return [ mode, MyPadding.Iso10126 ];
    }

    public static IEnumerable<object[]> NullTestData() {
        var modes = Enum.GetValues<MyCipherMode>();
        var paddings = Enum.GetValues<MyPadding>();
        var cipher = new DESCipher();
        var iv = GenerateValidIv();
        var key = GenKey(8);
        object[] args = [cipher];
        foreach (var mode in modes) {
            foreach (var pad in paddings) {
                yield return [ null, mode, pad, iv, args ];
                yield return [ key, mode, pad, null, args ];
                yield return [ key, mode, pad, iv, null ];
            }
        }
    }

    public static IEnumerable<object[]> NullFileTestData() {
        var modes = Enum.GetValues<MyCipherMode>();
        var paddings = Enum.GetValues<MyPadding>();
        var cipher = new DESCipher();
        var iv = GenerateValidIv();
        var key = GenKey(8);
        object[] args = [cipher];
        foreach (var mode in modes) {
            foreach (var pad in paddings) {
                yield return [ mode, pad, "null", null ];
                yield return [ mode, pad, "null", "" ];
                yield return [ mode, pad, "null", " " ];
                yield return [ mode, pad, "null", "null" ];

                yield return [ mode, pad, null, "null" ];
                yield return [ mode, pad, "", "null" ];
                yield return [ mode, pad, " ", "null" ];
                if (mode is MyCipherMode.OFB or MyCipherMode.CTR or MyCipherMode.RD) break;
            }
        }
    }
}
}
