import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;


public class EncryptionTest {
    @Test
    public void testGenerateKeyPair() throws Exception {
        KeyPair keyPair = Encryption.generateKeyPair();
        Assertions.assertNotNull(keyPair);
    }

    @Test
    public void testEncryptAndDecryptRSA() throws Exception {
        String message = "Hello, World!";
        KeyPair keyPair = Encryption.generateKeyPair();
        Key publicKey = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();

        byte[] encryptedMessage = Encryption.encryptRSA(message.getBytes(), publicKey);
        Assertions.assertNotNull(encryptedMessage);

        byte[] decryptedMessage = Encryption.decryptRSA(encryptedMessage, privateKey);
        Assertions.assertNotNull(decryptedMessage);
        Assertions.assertEquals(message, new String(decryptedMessage));
    }

    @Test
    public void testEncryptAndDecryptMessage() throws Exception {
        String message = "Hello world!";
        BigInteger privateKey= DiffieHellman.generatePrivateKey();
        BigInteger publicKey= DiffieHellman.generatePublicKey(privateKey);

        byte[] encryptedMessage = Encryption.encryptMessage(message.getBytes(), privateKey.toByteArray(), "AES", 16);
        Assertions.assertNotNull(encryptedMessage);

        byte[] decryptedMessage = Encryption.decryptMessage(encryptedMessage, publicKey.toByteArray(), "AES", 16);
        Assertions.assertNotNull(decryptedMessage);
        Assertions.assertEquals(message, new String(decryptedMessage));
    }
}

