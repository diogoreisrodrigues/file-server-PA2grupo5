import java.io.Serializable;

/**
 * This class represents a handshake client and server
 */
public class Handshake implements Serializable{
    private String username;
    private String encryptionAlgorithmType;
    private String encryptionAlgorithmName;
    private Integer encryptionKeySize;
    private String hashAlgorithmName;
    private Integer blockSize;

    /**
     * Constructor of Handshake objects
     *
     * @param username the name of the user that is initiating the handshake
     *
     * @param encryptionAlgorithmType the type of the encryption algorithm
     *
     * @param encryptionAlgorithmName the name of the encryption algorithm
     *
     * @param encryptionKeySize the size of the encryption key
     *
     * @param hashAlgorithmName the name of the hash algorithm
     *
     * @param blockSize the block size of the encryption algorithm
     */
    public Handshake(String username, String encryptionAlgorithmType, String encryptionAlgorithmName, Integer encryptionKeySize, String hashAlgorithmName, Integer blockSize) {
        this.username = username;
        this.encryptionAlgorithmType = encryptionAlgorithmType;
        this.encryptionAlgorithmName = encryptionAlgorithmName;
        this.encryptionKeySize = encryptionKeySize;
        this.hashAlgorithmName = hashAlgorithmName;
        this.blockSize = blockSize;
    }

    /**
     * Gets the name of the user that initiated the handshake
     *
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the type of the encryption algorithm used in the handshake
     *
     * @return the encryption algorithm type
     */
    public String getEncryptionAlgorithmType() {
        return encryptionAlgorithmType;
    }

    /**
     * Gets the name of the encryption algorithm used in the handshakes
     *
     * @return the algorithm encryption name
     */
    public String getEncryptionAlgorithmName() {
        return encryptionAlgorithmName;
    }

    /**
     * Gets the size of the encryption key used in the handshake
     *
     * @return the encryption key size
     */
    public Integer getEncryptionKeySize() {
        return encryptionKeySize;
    }

    /**
     * Gets the name of the hash algorithm used in the handshake
     *
     * @return the hash algorithm name
     */
    public String getHashAlgorithmName() {
        return hashAlgorithmName;
    }

    /**
     * Gets the block size of the encryption algorithm used in the handshake
     *
     * @return the block size
     */
    public Integer getBlockSize() {
        return blockSize;
    }
}
