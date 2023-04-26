/**
 * This is a utility class containing static method for manipulating byte arrays
 */
public class ByteUtils {

    /**
     * This method generates a byte array of a specified length filled with a given padding value
     *
     * @param padValue the byte value to use for padding
     *
     * @param padLength the length of the resulting byte array
     *
     * @return a byte array of length padLength filled with padValue
     */
    public static byte[] generatePad ( int padValue, int padLength ) {
        byte[] pad = new byte[padLength];
        for ( int i = 0; i < padLength; i++ ) {
            pad[i] = ( byte ) padValue;
        }
        return pad;
    }

    /**
     * This method computes XOR of two byte arrays of equal length
     *
     * @param a the first byte array
     *
     * @param b the second byte array
     *
     * @return a byte array containing the XOR of a and b
     */
    public static byte[] computeXor ( byte[] a, byte[] b ) {
        byte[] result = new byte[a.length];
        for ( int i = 0; i < a.length; i++ ) {
            result[i] = ( byte ) ( a[i] ^ b[i] );
        }
        return result;
    }

    /**
     * This method concatenates two byte arrays
     *
     * @param a the first byte array
     *
     * @param b the second byte array
     *
     * @return a byte array containing the concatenated contents of a and b
     */
    public static byte[] concatByteArrays ( byte[] a, byte[] b ) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy ( a, 0, result, 0, a.length );
        System.arraycopy ( b, 0, result, a.length, b.length );
        return result;
    }


}
