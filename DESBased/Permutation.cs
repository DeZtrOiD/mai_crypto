
namespace DESBased.Core.Permutation {
public class Permutation {
    /// <summary>
    /// Block permutation function.
    /// permutation[i] points to the bit that should be set to the i-th position.
    /// The default byte order is big-endian.
    /// </summary>
    public static byte[] Permute (
        in byte[] input,
        in int[] permutation,
        bool reverseOrder=false,
        bool startIndexFromZero=false
    ) {
        if ( input is null )
            throw new ArgumentNullException( "The input block is null." );
        if ( permutation is null )
            throw new ArgumentNullException( "The permutation rule is null." );

        int inBitCount = input.Length * 8;
        int outBitCount = permutation.Length;
        byte[] output = new byte[(outBitCount - 1 + 8) / 8];  // ceiling

        for (int bitIndex = 0; bitIndex < outBitCount; bitIndex++) {

            int srcBitIndex = permutation[bitIndex];
            if ( !startIndexFromZero ) srcBitIndex--;
            int dstBitIndex = bitIndex;
            if ( reverseOrder ) {
                srcBitIndex = inBitCount - srcBitIndex - 1;
                dstBitIndex = outBitCount - dstBitIndex - 1;
            }

            if (srcBitIndex >= inBitCount || srcBitIndex < 0 ||
                dstBitIndex >= outBitCount || dstBitIndex < 0
            ) {
                throw new IndexOutOfRangeException($"This permutation uses an invalid index at {bitIndex}-th position.");
            }

            int srcBit = 8 - 1 - srcBitIndex % 8;
            int dstBit = 8 - 1 - dstBitIndex % 8;

            int bitValue = ( input[srcBitIndex / 8] & (1 << srcBit) ) >> srcBit;  // Takes the value of a bit
            output[dstBitIndex / 8] |= (byte)( -bitValue & (1 << dstBit) );
        }
        return output;
    }
}
}
