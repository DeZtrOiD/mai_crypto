
using System.Security.Cryptography;

namespace DESBased.Core.Padding {
public static class PaddingProvider {
    public static byte[] Apply(byte[] data, int blockSize, MyPadding mode) {
        if ( blockSize <= 0 )  throw new ArgumentException("Block size must be positive.");
        if ( data is null ) throw new ArgumentNullException("The data is invalid.");

        int paddingLength = blockSize - (data.Length % blockSize);
        if (paddingLength == blockSize && mode is MyPadding.Zeros) return data;

        switch ( mode ) {
            case MyPadding.Zeros:
                return data.Concat(new byte[paddingLength]).ToArray();

            case MyPadding.AnsiX923: {
                byte[] pad = new byte[paddingLength];
                pad[^1] = (byte)paddingLength;
                return data.Concat(pad).ToArray();
            }

            case MyPadding.Pkcs7:
                return data.Concat(Enumerable.Repeat((byte)paddingLength, paddingLength)).ToArray();

            case MyPadding.Iso10126: {
                byte[] random = RandomNumberGenerator.GetBytes(paddingLength - 1);
                return data.Concat(random).Concat( [(byte)paddingLength] ).ToArray();
            }

            default: throw new NotSupportedException($"Padding mode { mode } is not supported.");
        }
    }

    public static byte[] Remove(byte[] data, MyPadding mode) {
        if ( data is null ) throw new ArgumentNullException(nameof(data));
        if ( data.Length == 0 ) return data;

        switch ( mode ) {
            case MyPadding.Zeros: {
                int i = data.Length - 1;
                while (i >= 0 && data[i] == 0) i--;
                return data[..(i + 1)];
            }

            case MyPadding.Pkcs7: {
                byte padLen = data[^1];
                if (padLen < 1 || padLen > data.Length ) throw new InvalidOperationException("Invalid PKCS#7 padding.");
                
                for (int i = 1; i <= padLen; i++) {
                    if (data[^i] != padLen) throw new InvalidOperationException("Invalid PKCS#7 padding.");
                }
                return data[..^padLen];
            }

            case MyPadding.AnsiX923: {
                byte padLen = data[^1];
                if (padLen < 1 || padLen > data.Length) throw new InvalidOperationException("Invalid ANSI X.923 padding.");
                
                for (int i = 2; i <= padLen; i++) {
                    if (data[^i] != 0) throw new InvalidOperationException("Invalid ANSI X.923 padding: non-zero padding byte detected.");
                }
                return data[..^padLen];
            }

            case MyPadding.Iso10126: {
                byte padLen = data[^1];
                if (padLen < 1 || padLen > data.Length)
                    throw new InvalidOperationException("Invalid ISO 10126 padding.");
                return data[..^padLen];
            }

            default: throw new NotSupportedException($"Padding mode {mode} is not supported.");;
        }
    }
}
}
