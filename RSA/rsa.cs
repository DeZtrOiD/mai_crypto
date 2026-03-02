using System.Numerics;
using System.Security.Cryptography;
using System.Buffers.Binary;

namespace RSA {
    public sealed class RSA {
        public enum PrimalityTest { Fermat, MillerRabin, SolovayStrassen }

        private BigInteger _n;
        private BigInteger _e;
        private BigInteger _d;
        private int _blockBytes;
        private int _maxDataSize;
        private readonly KeyGenerator _keyGenerator;

        private static int _paddingRandom = 8;
        private static int _paddingTag = 3;
        private static int _minBlockPadding = _paddingRandom + _paddingTag;

        public RSA( PrimalityTest primalityTest, double confidence, int keyBits ) {
            if( confidence < 0.5 || confidence >= 1.0 ) throw new ArgumentException( "Confidence must be in [0.5, 1)." );
            if( keyBits < 256 ) throw new ArgumentException( "keyBits >= 256" );

            _keyGenerator = new KeyGenerator( primalityTest, keyBits, confidence );
            GenerateNewKeyPair();
        }

        public void GenerateNewKeyPair() {
            var (n, e, d) = _keyGenerator.GenerateKeyPair();
            if( n.GetBitLength() < 504 ) throw new ArgumentException( "Key is less than 504 bits!" );
            _n = n; _e = e; _d = d;
            
            _blockBytes = ((int)n.GetBitLength() + 7) / 8;
            _maxDataSize = _blockBytes - _minBlockPadding;
        }

        public (BigInteger n, BigInteger e) GetNE => (_n, _e);
        public void SetNE(BigInteger n, BigInteger e) { _n=n; _e=e; }

        public async Task EncryptFileAsync( string inPath, string outPath, int bufferSize=8192 ) {
            await using var inFile = new FileStream(
                inPath, FileMode.Open, FileAccess.Read, 
                FileShare.Read, bufferSize, useAsync: true
            );
            
            await using var outFile = new FileStream(
                outPath, FileMode.Create, FileAccess.Write, 
                FileShare.None, bufferSize, useAsync: true
            );

            byte[] buffer = new byte[bufferSize];

            int length = 0;
            while( (length = await inFile.ReadAsync(buffer, 0, buffer.Length)) > 0 ) {

                var dataBlocks = DataToBlocks(buffer, length);
                var encrypted = new (int, byte[], int)[dataBlocks.Length];
                var options = new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };

                Parallel.ForEach( dataBlocks, options, block => {
                    encrypted[block.Index] = (block.Index, EncryptBlock(block.Data), block.Size);
                });

                foreach( var (_, block, size) in encrypted.OrderBy(x => x.Item1) ) {
                    var outBlock = GenerateMeta(block, size);
                    await outFile.WriteAsync( outBlock, 0, outBlock.Length );
                }
            }
        }

        public async Task DecryptFileAsync( string inPath, string outPath, int bufferSize=8192 ) {
            await using var inFile = new FileStream(
                inPath, FileMode.Open, FileAccess.Read, FileShare.Read, 
                bufferSize: bufferSize, useAsync: true
            );
            
            await using var outFile = new FileStream(
                outPath, FileMode.Create, FileAccess.Write, FileShare.None, 
                bufferSize: bufferSize, useAsync: true
            );

            using var binRead = new BinaryReader(inFile);
            
            var batchSize = Environment.ProcessorCount;

            var options = new ParallelOptions { MaxDegreeOfParallelism = batchSize };

            while (inFile.Position < inFile.Length) {
                var batch = await ReadBatchAsync(inFile, batchSize);
                if (batch.Count == 0) break;
                
                var decrypted = new byte[batch.Count][];
                Parallel.For(0, batch.Count, options, index => {
                    decrypted[index] = RemovePadding(DecryptBlock(batch[index].Data), batch[index].Size);
                });
                
                foreach (var block in decrypted)
                    if (block != null) await outFile.WriteAsync(block, 0, block.Length);
            }
        }

        private async Task<List<(int Size, byte[] Data)>> ReadBatchAsync(
            FileStream inFile,  int maxBlocks
        ) {
            var result = new List<(int, byte[])>(maxBlocks);
            if (inFile.Position >= inFile.Length) return result;
            
            const int HeaderSize = 4;
            int recordSize = HeaderSize + _blockBytes;
            
            long remainingBytes = inFile.Length - inFile.Position;
            int blocksToRead = (int)Math.Min(maxBlocks, remainingBytes / recordSize);
            
            if (blocksToRead == 0) {
                if (remainingBytes > 0) {
                    throw new CryptographicException(
                        $"Corrupted file: incomplete block. Expected {recordSize} bytes per record, but only {remainingBytes} bytes remaining.");
                }
                return result;
            }
            
            byte[] batchBuffer = new byte[blocksToRead * recordSize];
            await inFile.ReadExactlyAsync(batchBuffer);
            
            for (int i = 0; i < blocksToRead; i++) {
                int offset = i * recordSize;
                
                int size = BinaryPrimitives.ReadInt32LittleEndian(
                    batchBuffer.AsSpan(offset, HeaderSize)
                );                
                byte[] encryptedBlock = new byte[_blockBytes];
                Array.Copy(batchBuffer, offset + HeaderSize, encryptedBlock, 0, _blockBytes);

                result.Add((size, encryptedBlock));
            }
            return result;
        }

        // PKCS #1: RSA Encryption Version 1.5
        private byte[] GeneratePadding( Span<byte> data ) {
            byte[] res = new byte[_blockBytes];
            res[0] = 0x0;
            res[1] = 0x2;

            var paddingLength = _blockBytes - data.Length;
            var randomBegin = 2;
            var randomLength = paddingLength - _paddingTag;
            for( int i = 0; i < randomLength; i++ )
                res[i + randomBegin] = (byte)RandomNumberGenerator.GetInt32(1, 256);

            res[randomBegin + randomLength] = 0x0;

            data.CopyTo( res.AsSpan(paddingLength) );
            return res;
        }

        private byte[] RemovePadding( byte[] data, int originalSize ) {
            byte[] res = new byte[originalSize];

            var paddingLength = _blockBytes - originalSize;
            data.AsSpan(paddingLength).CopyTo(res.AsSpan(0));
            return res;
        }

        private byte[] GenerateMeta( byte[] data, int originalSize ) {
            byte[] res = new byte[data.Length + 4];
            BinaryPrimitives.WriteInt32LittleEndian(res, originalSize);

            Array.Copy(data, 0, res, 4, data.Length);
            return res;
        }

        private (int Index, byte[] Data, int Size)[] DataToBlocks( byte[] data, int dataSize ) {
            int blockCount = (dataSize + _maxDataSize - 1) / _maxDataSize;
            var blocks = new (int, byte[], int)[blockCount];

            for( int i = 0; i < blockCount; i++ ) {
                var begin = i * _maxDataSize;
                var size = Math.Min( _maxDataSize, dataSize - begin );
                var padded = GeneratePadding(data.AsSpan(begin, size));
                blocks[i] = (i, padded, size);
            }
            return blocks;
        }

        private byte[] EncryptBlock( byte[] data ) {
            BigInteger message = new BigInteger(data, isUnsigned: true, isBigEndian: true);
            BigInteger cipher = NumberTheoryService.ModPow( message, _e, _n );
            
            byte[] bytes = cipher.ToByteArray( true, true );
            byte[] res = new byte[data.Length];
            Array.Copy(bytes, 0, res, data.Length - bytes.Length, bytes.Length);  // zero pad
            return res;
        }

        private byte[] DecryptBlock( byte[] data ) {
            BigInteger cipher = new BigInteger(data, isUnsigned: true, isBigEndian: true);
            BigInteger message = NumberTheoryService.ModPow( cipher, _d, _n );

            byte[] bytes = message.ToByteArray( true, true );
            byte[] res = new byte[data.Length];
            Array.Copy(bytes, 0, res, data.Length - bytes.Length, bytes.Length);
            return res;
        }

        public sealed class KeyGenerator {
            private readonly IProbabilisticPrimalityTest _primalityTestImpl;
            private readonly int _keyBits;
            private readonly double _confidence;
            private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

            public KeyGenerator( PrimalityTest primalityTest, int keyBits, double confidence ) {
                _keyBits = keyBits >= 256 ? keyBits : throw new ArgumentException( "keyBits >= 256" );
                _confidence = confidence;

                switch( primalityTest ) {
                    case PrimalityTest.Fermat:
                        _primalityTestImpl = new FermatPrimalityTest();
                        break;
                    case PrimalityTest.MillerRabin:
                        _primalityTestImpl = new MillerRabinPrimalityTest();
                        break;
                    case PrimalityTest.SolovayStrassen:
                        _primalityTestImpl = new SolovayStrassenPrimalityTest();
                        break;
                    default:
                        throw new NotSupportedException();
                }
            }

            public (BigInteger n, BigInteger e, BigInteger d) GenerateKeyPair() {
                BigInteger p;
                BigInteger q;
                BigInteger n;
                BigInteger phi;
                BigInteger e = 65537;
                BigInteger d;
                BigInteger minPrimeDifference = BigInteger.One << 80;
                while( true ) {
                    p = GenerateNextPrime();
                    q = GenerateNextPrime();
                    if( BigInteger.Abs(p - q) < minPrimeDifference ) continue;

                    n = p * q;
                    phi = (p - 1) * (q - 1);

                    if( NumberTheoryService.Gcd( e, phi ) != 1 ) continue;

                    d = ModInverse(e, phi);
                    if( d < CalculateMinimumD( n ) ) continue;
                    
                    return ( n, e, d );
                }
            }

            private static BigInteger ModInverse(BigInteger a, BigInteger m) {
                var (gcd, x, _) = NumberTheoryService.ExtendedGcd(a, m);
                if( gcd != 1 ) throw new ArgumentException("Modular inverse does not exist.");
                if( x < 0 ) x += m;
                return x;
            }

            private BigInteger GenerateNextPrime() {
                BigInteger candidate;
                do {
                    int primeBits = (_keyBits + 1) / 2;
                    var randomBytes = new byte[( primeBits + 7 ) / 8];
                    _rng.GetBytes( randomBytes );
                    candidate = new BigInteger( randomBytes, isUnsigned: true, isBigEndian: true );
                    if( candidate.Sign < 0 ) candidate = -candidate;
                    candidate |= BigInteger.One << ( primeBits - 1 );
                    candidate |= BigInteger.One;
                } while( !_primalityTestImpl.IsPrime( candidate, _confidence ) );

                return candidate;
            }

            private BigInteger CalculateMinimumD( BigInteger modulus ) {
                return NumberTheoryService.IntegerSquareRoot(
                    NumberTheoryService.IntegerSquareRoot(modulus)
                ) / 3;
            }
        }  // KeyGenerator
    }
}