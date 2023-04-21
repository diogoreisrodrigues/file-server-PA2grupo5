import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;

/**
 * This class represents the client handler. It handles the communication with the client. It reads the file from the
 * server and sends it to the client.
 */
public class ClientHandler extends Thread {

    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final Socket client;
    private final boolean isConnected;
    private final PrivateKey privateRSAKey;
    private final PublicKey publicRSAKey;
    private PublicKey senderPublicRSAKey;

    /**
     * Creates a ClientHandler object by specifying the socket to communicate with the client. All the processing is
     * done in a separate thread.
     *
     * @param client the socket to communicate with the client
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public ClientHandler ( Socket client ) throws Exception {
        this.client = client;
        in = new ObjectInputStream ( client.getInputStream ( ) );
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
        KeyPair keyPair = Encryption.generateKeyPair ( );
        this.privateRSAKey = keyPair.getPrivate ( );
        this.publicRSAKey = keyPair.getPublic ( );
        senderPublicRSAKey = rsaKeyDistribution ( in );
    }

    private BigInteger agreeOnSharedSecret ( PublicKey senderPublicRSAKey ) throws Exception {
        // Generate a pair of keys
        BigInteger privateKey = DiffieHellman.generatePrivateKey ( );
        BigInteger publicKey = DiffieHellman.generatePublicKey ( privateKey );
        // Extracts the public key from the request
        BigInteger clientPublicKey = new BigInteger ( Encryption.decryptRSA ( ( byte[] ) in.readObject ( ) , senderPublicRSAKey ) );
        // Send the public key to the client
        sendPublicDHKey ( publicKey );
        // Generates the shared secret
        return DiffieHellman.computePrivateKey ( clientPublicKey , privateKey );
    }

    private void sendPublicDHKey ( BigInteger publicKey ) throws Exception {
        out.writeObject ( Encryption.encryptRSA ( publicKey.toByteArray ( ) , this.privateRSAKey ) );
    }

    @Override
    public void run ( ) {
        super.run ( );
        BigInteger sharedSecret = null;
        try {
            sharedSecret = agreeOnSharedSecret ( senderPublicRSAKey );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        try {
            while ( isConnected ) {

                Message messageObj = ( Message ) in.readObject ( );
                // Extracts and decrypt the message
                byte[] decryptedMessage = Encryption.decryptMessage ( messageObj.getMessage ( ) , sharedSecret.toByteArray ( ) );
                // Extracts the MAC
                byte[] digest = messageObj.getSignature ( );
                // Verifies the MAC
                MessageDigest messageDigest = MessageDigest.getInstance ( "SHA-1" );
                //String hmacKey = "5v8y/B?E";
                byte[] result = HMAC.computeHMAC ( decryptedMessage , sharedSecret.toByteArray() , 64 , messageDigest );
                System.out.println ( "Message HMAC: " + new String ( result ) );

                if ( !Arrays.equals(result, digest) ) {
                    System.out.println ( "MAC verification failed" );
                    closeConnection ( );
                    return;
                }

                String request = new String ( decryptedMessage );
                System.out.println ( "Request: " + request );
                // Reads the file and sends it to the client
                byte[] content = FileHandler.readFile ( RequestUtils.getAbsoluteFilePath ( request ) );

                sendFile ( content, sharedSecret );
            }
            // Close connection
            closeConnection ( );
        } catch (Exception e ) {
            // Close connection
            closeConnection ( );
        }
    }

    private PublicKey rsaKeyDistribution(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // Extract the public key
        PublicKey senderPublicRSAKey = ( PublicKey ) in.readObject ( );
        // Send the public key
        sendPublicRSAKey ( );
        return senderPublicRSAKey;
    }

    private void sendPublicRSAKey ( ) throws IOException {
        out.writeObject ( publicRSAKey );
        out.flush ( );
    }

    /**
     * Sends the file to the client
     *
     * @param content the content of the file to send
     *
     * @throws IOException when an I/O error occurs when sending the file
     */
    private void sendFile ( byte[] content, BigInteger sharedSecret ) throws Exception {

        byte[] encryptedMessage = Encryption.encryptMessage ( content , sharedSecret.toByteArray ( ) );
        // Computes the HMAC of the message
        MessageDigest messageDigest = MessageDigest.getInstance ( "SHA-1" );
        //String hmacKey = "5v8y/B?E";
        byte[] result = HMAC.computeHMAC ( content , sharedSecret.toByteArray() , 64 , messageDigest );
        System.out.println ( "Message HMAC: " + new String ( result ) );
        // Creates the message object
        Message response = new Message ( encryptedMessage, result);

        out.writeObject ( response );
        out.flush ( );
    }


    /**
     * Closes the connection by closing the socket and the streams.
     */
    private void closeConnection ( ) {
        try {
            client.close ( );
            out.close ( );
            in.close ( );
        } catch ( IOException e ) {
            throw new RuntimeException ( e );
        }
    }

}
