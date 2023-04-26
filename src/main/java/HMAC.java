import java.security.MessageDigest;

/**
 * This class provides a static method for computing an HMAC using a given message, key, block size and message digest algorithm
 */
public class HMAC {

    /**
     * Computes an HMAC using the parameters
     *
     * @param message the message to compute the HMAC for
     *
     * @param key the key to use for computing the HMAC
     *
     * @param blocksize the block size to use for the HMAC computation
     *
     * @param messageDigest the message digest algorithm to use for the HMAC computation
     *
     * @return the computed HMAC as a byte array
     */
    public static byte[] computeHMAC ( byte[] message , byte[] key, int blocksize, MessageDigest messageDigest ){

        byte[] kPrime = computeBlockSizedKey(key, blocksize, messageDigest);
        byte[] opad = ByteUtils.generatePad (0x5c, blocksize);
        byte[] kPrimeWithOpad = ByteUtils.computeXor(kPrime, opad);
        byte[] kPrimeWithIpadMessage = ByteUtils.concatByteArrays(kPrime, message);
        byte[] hashedKPrimeWithIpadMessage = messageDigest.digest(kPrimeWithIpadMessage);
        byte[] argDiggest = ByteUtils.concatByteArrays(kPrimeWithOpad, hashedKPrimeWithIpadMessage);
        return messageDigest.digest(argDiggest);

    }

    /**
     * Computes a block-sized key form the specified key
     *
     * @param key the key to compute a block-sized key from
     *
     * @param blocksize the block size to use for the HMAC computation
     *
     * @param messageDigest the message digest algorithm to use for the HMAC computation
     *
     * @return the computed block-sized key as a byte array
     */
    private static byte[] computeBlockSizedKey(byte[] key, int blocksize, MessageDigest messageDigest) {
        if(key.length > blocksize){
            return messageDigest.digest(key);
        }
        if(key.length < blocksize){
            byte[] blockSizedKey = new byte[blocksize];
            System.arraycopy(key, 0, blockSizedKey, 0, key.length);
            for (int i = key.length; i < blocksize; i++) {
                blockSizedKey[i] = 0x00;
            }
            return blockSizedKey;
        }
        else{
            return key;
        }
    }
}
