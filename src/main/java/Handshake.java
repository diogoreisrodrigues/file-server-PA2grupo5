import java.io.Serializable;

public class Handshake implements Serializable{
    private String username;
    private String encryptionAlgorithmType;
    private String encryptionAlgorithmName;
    private Integer encryptionKeySize;
    private String hashAlgorithmName;
    private Integer blockSize;

    public Handshake(String username, String encryptionAlgorithmType, String encryptionAlgorithmName, Integer encryptionKeySize, String hashAlgorithmName, Integer blockSize) {
        this.username = username;
        this.encryptionAlgorithmType = encryptionAlgorithmType;
        this.encryptionAlgorithmName = encryptionAlgorithmName;
        this.encryptionKeySize = encryptionKeySize;
        this.hashAlgorithmName = hashAlgorithmName;
        this.blockSize = blockSize;
    }

    public String getUsername() {
        return username;
    }

    public String getEncryptionAlgorithmType() {
        return encryptionAlgorithmType;
    }

    public String getEncryptionAlgorithmName() {
        return encryptionAlgorithmName;
    }

    public Integer getEncryptionKeySize() {
        return encryptionKeySize;
    }

    public String getHashAlgorithmName() {
        return hashAlgorithmName;
    }

    public Integer getBlockSize() {
        return blockSize;
    }
}
