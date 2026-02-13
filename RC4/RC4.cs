
public class RC4 {
    private byte[] _S;
    private int _i;
    private int _j;

    public RC4( byte[] key ) {
        if( key is null || key.Length == 0 )
            throw new ArgumentException("RC4 key must not be null or empty.");

        _S = new byte[256];
        for( int i = 0; i < _S.Length; i++ ) _S[i] = (byte)i;
        Shuffle(_S, key);

        _i = 0;
        _j = 0;
    }

    private void Shuffle( byte[] s, byte[] key ) {
        int j = 0;
        for (int i = 0; i < 256; i++) {
            byte k = key[i % key.Length];
            j = (j + s[i] + k) % 256;
            (s[i], s[j]) = (s[j], s[i]);
        }
    }

    public void ProcessChunk( byte[] chunk, int chunkLength ) {
        byte[] s = _S;

        for( int k = 0; k < chunkLength; k++ ) {
            _i = (_i + 1) % 256;
            _j = (_j + s[_i]) % 256;
            Swap(_S, _i, _j);

            int t = (_S[_i] + _S[_j]) % 256;
            chunk[k] ^= _S[t];
        }
    }

    private static void Swap( byte[] array, int i, int j ) =>
        (array[i], array[j]) = (array[j], array[i]);
}


public static class RC4Async {
    private const int AsyncCipherThreshold = 4096 * 512;
    public static async Task EncryptFileAsync( string inPath, string outPath, byte[] key, int bufferSize ) {
        if ( string.IsNullOrEmpty(inPath) )
            throw new ArgumentException("Input path must not be empty!");
        if ( string.IsNullOrEmpty(outPath) )
            throw new ArgumentException("Output path must not be empty!");
        if ( bufferSize < 1 )
            throw new ArgumentOutOfRangeException("Buffer must be at least 1 byte long");

        var cipher = new RC4(key);

        using var inF = new FileStream(
            inPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, useAsync: true
        );
        using var outF = new FileStream(
            outPath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize, useAsync: true
        );

        byte[] buffer = new byte[bufferSize];
        int readBytes = 0;
        while( (readBytes = await inF.ReadAsync(buffer, 0, buffer.Length)) > 0 ) {
            
            if ( readBytes > AsyncCipherThreshold )
                await Task.Run( () => cipher.ProcessChunk(buffer, readBytes) );
            else cipher.ProcessChunk(buffer, readBytes);

            await outF.WriteAsync( buffer, 0, readBytes );
        }
    }


    public static Task DecryptFileAsync( string inPath, string outPath, byte[] key, int bufferSize ) =>
        EncryptFileAsync( inPath, outPath, key, bufferSize );
}
