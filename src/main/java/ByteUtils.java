public class ByteUtils {

        public static byte[] generatePad ( int padValue, int padLength ) {
            byte[] pad = new byte[padLength];
            for ( int i = 0; i < padLength; i++ ) {
                pad[i] = ( byte ) padValue;
            }
            return pad;
        }

        public static byte[] computeXor ( byte[] a, byte[] b ) {
            byte[] result = new byte[a.length];
            for ( int i = 0; i < a.length; i++ ) {
                result[i] = ( byte ) ( a[i] ^ b[i] );
            }
            return result;
        }

        public static byte[] concatByteArrays ( byte[] a, byte[] b ) {
            byte[] result = new byte[a.length + b.length];
            System.arraycopy ( a, 0, result, 0, a.length );
            System.arraycopy ( b, 0, result, a.length, b.length );
            return result;
        }


}
