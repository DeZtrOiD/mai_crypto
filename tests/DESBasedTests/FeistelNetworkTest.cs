

using DESBased.Core.Interfaces;

namespace DESBased.Core.Ciphers.Tests {
public class FeistelNetworkTests {

    [Fact]
    public void ConstructorNullKeyScheduleOrRoundFunctionShouldThrow() {
        Assert.Throws<ArgumentNullException>(() => new FeistelNetwork(null!, new MockRoundFunction()));
        Assert.Throws<ArgumentNullException>(() => new FeistelNetwork(new MockKeySchedule(16), null!));
    }

    [Fact]
    public void InvalidPropertiesShouldThrow() {
        var f = new FeistelNetwork(new MockKeySchedule(1), new MockRoundFunction());
        f.BlockSize = 1; f.RoundCount = 1;
        Assert.Throws<ArgumentOutOfRangeException>(() => f.BlockSize = 0);
        Assert.Throws<ArgumentOutOfRangeException>(() => f.RoundCount = 0);
        Assert.Throws<ArgumentOutOfRangeException>(() => f.BlockSize = -1);
        Assert.Throws<ArgumentOutOfRangeException>(() => f.RoundCount = -1);
    }

    [Fact]
    public void InvalidInitShouldThrow() {
        var feistel = new FeistelNetwork(new MockKeySchedule(10), new MockRoundFunction());
        feistel.RoundCount = 10;
        Assert.Throws<ArgumentNullException>(() => feistel.Init(null!));
        Assert.Throws<ArgumentException>(() => feistel.Init(Array.Empty<byte>()));
        feistel.RoundCount = 16;
        Assert.Throws<InvalidOperationException>(() => feistel.Init(new byte[8]));
    }

    [Fact]
    public void EncryptOrDecryptNotInitializedShouldThrow() {
        var feistel = new FeistelNetwork(new MockKeySchedule(16), new MockRoundFunction());
        Assert.Throws<InvalidOperationException>(() => feistel.Encrypt(new byte[8]));
        Assert.Throws<InvalidOperationException>(() => feistel.Decrypt(new byte[8]));
    }

    [Fact]
    public void EncryptOrDecryptNullBlockShouldThrow() {
        var feistel = new FeistelNetwork(new MockKeySchedule(16), new MockRoundFunction());
        feistel.Init(new byte[8]);
        Assert.Throws<ArgumentNullException>(() => feistel.Encrypt(null!));
        Assert.Throws<ArgumentNullException>(() => feistel.Decrypt(null!));
    }

    [Fact]
    public void EncryptOrDecryptInvalidBlockSizeShouldThrow() {
        var feistel = new FeistelNetwork(new MockKeySchedule(16), new MockRoundFunction());
        feistel.Init(new byte[8]);
        Assert.Throws<ArgumentException>(() => feistel.Encrypt(new byte[7]));
        Assert.Throws<ArgumentException>(() => feistel.Encrypt(new byte[9]));
        Assert.Throws<ArgumentException>(() => feistel.Decrypt(new byte[7]));
        Assert.Throws<ArgumentException>(() => feistel.Decrypt(new byte[9]));
    }

    [Theory]
    [MemberData( nameof(RoundTripCases) )]
    public void RoundTripShouldRecoverPlaintext(
        int blockSize, int rounds, byte[] key, byte[] block, byte roundConst
    ) {
        var feistel = new FeistelNetwork(
            new MockKeySchedule(rounds, true),
            new MockRoundFunction(roundConst)
        );
        feistel.BlockSize = blockSize;
        feistel.RoundCount = rounds;

        feistel.Init(key);
        var encrypted = feistel.Encrypt(block);

        Assert.NotEqual(block, encrypted);
        Assert.Equal(block, feistel.Decrypt(encrypted));
    }

    [Fact]
    public void FeistelPropertyDifferentKeysProduceDifferentCiphertexts() {
        var feistel1 = new FeistelNetwork( new MockKeySchedule(8, true), new MockRoundFunction() );
        feistel1.BlockSize = 8; feistel1.RoundCount = 8;
        var feistel2 = new FeistelNetwork( new MockKeySchedule(8, true), new MockRoundFunction() );
        feistel2.BlockSize = 8; feistel2.RoundCount = 8;

        byte[] block = [ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 ];

        feistel1.Init([ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF ]);
        feistel2.Init([ 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 ]);

        var enc1 = feistel1.Encrypt(block);
        var enc2 = feistel2.Encrypt(block);
        
        Assert.NotEqual(enc1, enc2);
        
        Assert.Equal(block, feistel1.Decrypt(enc1));
        Assert.Equal(block, feistel2.Decrypt(enc2));
    }

    [Fact]
    public void FeistelPropertySameKeySamePlaintextProducesSameCiphertext() {
        var feistel = new FeistelNetwork( new MockKeySchedule(16, true), new MockRoundFunction() );
        feistel.BlockSize = 8; feistel.RoundCount = 16;
        var feistel2 = new FeistelNetwork( new MockKeySchedule(16, true), new MockRoundFunction() );
        feistel2.BlockSize = 8; feistel2.RoundCount = 16;

        byte[] key = [ 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 ];
        byte[] block = [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF ];
        
        feistel.Init(key);
        feistel2.Init(key);

        Assert.Equal(feistel.Encrypt(block), feistel2.Encrypt(block));
    }

    private static byte[] GenByteSequence(int count, bool reverse=false) {
            if ( !reverse ) return Enumerable.Range(0, count).Select( i => (byte)i ).ToArray();
            return Enumerable.Range(0, count).Select( i => (byte)(0xFF - i) ).ToArray();
    }

    public static IEnumerable<object[]> RoundTripCases() {
        yield return [ 8, 4, GenByteSequence(8), GenByteSequence(8, true), (byte)0x33 ];
        yield return [ 8, 1, GenByteSequence(8), GenByteSequence(8, true), (byte)0x33 ];
        yield return [ 16, 8, GenByteSequence(16), GenByteSequence(16, true), (byte)0x77 ];
        yield return [ 8, 16, GenByteSequence(8), new byte[8], (byte)0xAA ];  // all zeros
        yield return [ 8, 16, GenByteSequence(8), Enumerable.Repeat((byte)0xFF, 8).ToArray(), (byte)0x55 ];  // all ones
    }

    private class MockKeySchedule : IKeySchedule {
        private readonly int _roundCount;
        private readonly byte _keyByte;
        private readonly bool _keyDependent;

        public MockKeySchedule(int roundCount, bool keyDependent = false, byte keyByte = 0xAA) {
            _roundCount = roundCount;
            _keyByte = keyByte;
            _keyDependent = keyDependent;
        }

        public byte[][] GenerateRoundKeys(in byte[] key) {
            if (_keyDependent && (key is null || key.Length == 0))
                throw new ArgumentException("Key cannot be null or empty.", nameof(key));

            var keys = new byte[_roundCount][];
            for (int i = 0; i < _roundCount; i++) {
                if (!_keyDependent) {
                    keys[i] = Enumerable.Repeat((byte)(_keyByte ^ i), 4).ToArray();
                } else {
                    keys[i] = new byte[4];
                    for (int j = 0; j < 4; j++) {
                        keys[i][j] = (byte)(key[j % key.Length] ^ (byte)i ^ (byte)j);
                    }
                }
            }
            return keys;
        }
    }

    private class MockRoundFunction : IRoundFunction {
        private readonly byte _constant;

        public MockRoundFunction(byte constant = 0x55) {
            _constant = constant;
        }

        public byte[] Transform(in byte[] halfBlock, in  byte[] roundKey) {
            var result = new byte[halfBlock.Length];
            for (int i = 0; i < halfBlock.Length; i++) {
                result[i] = (byte)(halfBlock[i] ^ _constant ^ roundKey[i % roundKey.Length]);
            }
            return result;
        }
    }
}
}
