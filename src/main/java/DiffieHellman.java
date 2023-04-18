import java.security.*;


public class DiffieHellman {

    private KeyPairGenerator keyGen;
    private KeyPair keyPair;

    public PrivateKey generatePrivateKey() {
        try {
            keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            keyPair = keyGen.generateKeyPair();
            return keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public PublicKey generatePublicKey() {
        try {
            keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            keyPair = keyGen.generateKeyPair();
            return keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
