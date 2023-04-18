import java.security.MessageDigest;

public class HMAC {

    public static byte[] computeMAC ( byte[] message , byte[] key, int blocksize, MessageDigest messageDigest ){

        byte[] kPrime = computeBlockSizedKey(key, blocksize, messageDigest);
        byte[] opad = ByteUtils.generatePad (0x5c, blocksize);
        byte[] kPrimeWithOpad = ByteUtils.computeXor(kPrime, opad);
        byte[] kPrimeWithIpadMessage = ByteUtils.concatByteArrays(kPrime, message);
        byte[] hashedKPrimeWithIpadMessage = messageDigest.digest(kPrimeWithIpadMessage);
        byte[] argDiggest = ByteUtils.concatByteArrays(kPrimeWithOpad, hashedKPrimeWithIpadMessage);
        return messageDigest.digest(argDiggest);

    }

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
