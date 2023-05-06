import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * This class provides methods to encrypt and decrypt messages using RSA encryption and a symmetric encryption with the secret key
 */
public class Encryption {

    /**
     * This generates a new RSA key pair with 2048-bit key size
     *
     * @return a new RSA KeyPair object containing a public and a private key
     *
     * @throws Exception if there is an error generating the key pair
     */
    public static KeyPair generateKeyPair ( ) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance ( "RSA" );
        keyPairGenerator.initialize ( 2048 );
        return keyPairGenerator.generateKeyPair ( );
    }

    /**
     * This encrypts a message using RSA encryption with the given public key
     *
     * @param message the message to encrypt
     *
     * @param publicKey the public key to use for encryption
     *
     * @return the encrypted message
     *
     * @throws Exception if is an error during the encryption process
     */
    public static byte[] encryptRSA ( byte[] message , Key publicKey ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "RSA" );
        cipher.init ( Cipher.ENCRYPT_MODE , publicKey );
        return cipher.doFinal ( message );
    }

    /**
     * This decrypts a message using RSA encryption and the provided private key.
     *
     * @param message the message to decrypt
     *
     * @param privateKey the private key to use ofr decryption
     *
     * @return the decrypted message as a byte array
     *
     * @throws Exception if is an issue with the decryption process
     */
    public static byte[] decryptRSA ( byte[] message , Key privateKey ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "RSA" );
        cipher.init ( Cipher.DECRYPT_MODE , privateKey );
        return cipher.doFinal ( message );
    }

    /**

     Decrypts the given message using the provided secret key and encryption algorithm.
     @param message the message to be decrypted as an array of bytes
     @param secretKey the secret key used for decryption as an array of bytes
     @param chosenAlgorithm the encryption algorithm used for decryption as a string
     @param keySize the size of the secret key as an integer
     @return the decrypted message as an array of bytes
     @throws Exception if the decryption fails
     */
    public static byte[] decryptMessage ( byte[] message , byte[] secretKey,  String chosenAlgorithm, int keySize ) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate ( keySize ).put ( secretKey ).array ( );
        SecretKeySpec secreteKeySpec = new SecretKeySpec ( secretKeyPadded , chosenAlgorithm );
        Cipher cipher = Cipher.getInstance (  chosenAlgorithm+"/ECB/PKCS5Padding" );
        cipher.init ( Cipher.DECRYPT_MODE , secreteKeySpec );
        return cipher.doFinal ( message );
    }


    /**

     Encrypts a message using the specified secret key and encryption algorithm.
     @param message the message to be encrypted
     @param secretKey the secret key used to encrypt the message
     @param chosenAlgorithm the chosen encryption algorithm
     @param keySize the key size used for the encryption
     @return the encrypted message as an array of bytes
     @throws Exception when the encryption fails

     */
    public static byte[] encryptMessage ( byte[] message , byte[] secretKey, String chosenAlgorithm, int keySize ) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate ( keySize ).put ( secretKey ).array ( );
        SecretKeySpec secreteKeySpec = new SecretKeySpec ( secretKeyPadded , chosenAlgorithm );
        Cipher cipher = Cipher.getInstance ( chosenAlgorithm+"/ECB/PKCS5Padding" );
        cipher.init ( Cipher.ENCRYPT_MODE , secreteKeySpec );
        return cipher.doFinal ( message );
    }
}
