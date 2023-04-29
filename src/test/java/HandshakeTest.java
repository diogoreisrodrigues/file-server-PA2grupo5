import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class HandshakeTest {

    @Test
    public void testConstructor() {
        String username = "testuser";
        String encryptionAlgorithmType = "AES";
        String encryptionAlgorithmName = "AES/CBC/PKCS5Padding";
        Integer encryptionKeySize = 256;
        String hashAlgorithmName = "SHA-256";
        Integer blockSize = 16;

        Handshake handshake = new Handshake(username, encryptionAlgorithmType, encryptionAlgorithmName,
                encryptionKeySize, hashAlgorithmName, blockSize);

        assertEquals(username, handshake.getUsername());
        assertEquals(encryptionAlgorithmType, handshake.getEncryptionAlgorithmType());
        assertEquals(encryptionAlgorithmName, handshake.getEncryptionAlgorithmName());
        assertEquals(encryptionKeySize, handshake.getEncryptionKeySize());
        assertEquals(hashAlgorithmName, handshake.getHashAlgorithmName());
        assertEquals(blockSize, handshake.getBlockSize());
    }

    @Test
    public void testGetters() {
        String username = "testuser";
        String encryptionAlgorithmType = "AES";
        String encryptionAlgorithmName = "AES/CBC/PKCS5Padding";
        Integer encryptionKeySize = 256;
        String hashAlgorithmName = "SHA-256";
        Integer blockSize = 16;

        Handshake handshake = new Handshake(username, encryptionAlgorithmType, encryptionAlgorithmName,
                encryptionKeySize, hashAlgorithmName, blockSize);

        assertEquals(username, handshake.getUsername());
        assertEquals(encryptionAlgorithmType, handshake.getEncryptionAlgorithmType());
        assertEquals(encryptionAlgorithmName, handshake.getEncryptionAlgorithmName());
        assertEquals(encryptionKeySize, handshake.getEncryptionKeySize());
        assertEquals(hashAlgorithmName, handshake.getHashAlgorithmName());
        assertEquals(blockSize, handshake.getBlockSize());
    }
}

