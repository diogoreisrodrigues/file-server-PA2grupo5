import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;

/**
 * This class represents the client. The client sends the messages to the server by means of a socket. The use of Object
 * streams enables the sender to send any kind of object.
 */
public class Client {

    private static final String HOST = "0.0.0.0";
    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final boolean isConnected;
    private final String userDir;
    private final PrivateKey privateRSAKey;
    private final PublicKey publicRSAKey;
    
    private PublicKey receiverPublicRSAKey;

    /**
     * Constructs a Client object by specifying the port to connect to. The socket must be created before the sender can
     * send a message.
     *
     * @param port the port to connect to
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public Client ( int port ) throws Exception {
        client = new Socket ( HOST , port );
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        in = new ObjectInputStream ( client.getInputStream ( ) );
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
        // Generates the RSA key pair that will be used for the Diffie-Hellman key exchange
        KeyPair keyPair = Encryption.generateKeyPair ( );
        this.privateRSAKey = keyPair.getPrivate ( );
        this.publicRSAKey = keyPair.getPublic ( );
        // Performs the RSA key distribution
        receiverPublicRSAKey = rsaKeyDistribution ( );
        // Create a temporary directory for putting the request files
        userDir = Files.createTempDirectory ( "fileServer" ).toFile ( ).getAbsolutePath ( );
        System.out.println ( "Temporary directory path " + userDir );
        askUsername();
        BigInteger sharedSecret = agreeOnSharedSecret(receiverPublicRSAKey);
        execute(sharedSecret);

    }

    private PublicKey rsaKeyDistribution ( ) throws Exception {
        // Sends the public key
        sendPublicRSAKey ( );
        // Receive the public key of the sender
        return ( PublicKey ) in.readObject ( );
    }

    private void sendPublicRSAKey() {
        try {
            out.writeObject ( publicRSAKey );
            out.flush ( );
        } catch ( IOException e ) {
            e.printStackTrace ( );
        }
    }

    private BigInteger agreeOnSharedSecret ( PublicKey receiverPublicRSAKey ) throws Exception {
        // Generates a private key
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey ( );
        BigInteger publicDHKey = DiffieHellman.generatePublicKey ( privateDHKey );
        // Sends the public key to the server encrypted
        sendPublicDHKey ( Encryption.encryptRSA ( publicDHKey.toByteArray ( ) , privateRSAKey ) );
        // Waits for the server to send his public key
        BigInteger serverPublicKey = new BigInteger ( Encryption.decryptRSA ( ( byte[] ) in.readObject ( ) , receiverPublicRSAKey ) );
        // Generates the shared secret
        return DiffieHellman.computePrivateKey ( serverPublicKey , privateDHKey );
    }
    /**
     * Sends the public key to the receiver.
     *
     * @param publicKey the public key to send
     *
     * @throws Exception when the public key cannot be sent
     */
    private void sendPublicDHKey ( byte[] publicKey ) throws Exception {
        out.writeObject ( publicKey );
    }

    private void askUsername() {
        Scanner inputScanner = new Scanner(System.in);
        System.out.print("Enter new username: ");
        String newUsername = inputScanner.nextLine();
        //clientHandshake = new Handshake(newUsername, clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), clientHandshake.publicKey(), clientHandshake.encryptionAlgorithmName(), clientHandshake.blockSize());
    }


    /**
     * Executes the client. It reads the file from the console and sends it to the server. It waits for the response and
     * writes the file to the temporary directory.
     */
    public void execute ( BigInteger sharedSecret ) {
        Scanner usrInput = new Scanner ( System.in );
        try {
            while ( isConnected ) {
                // Reads the message to extract the path of the file
                System.out.println ( "Write the path of the file" );
                String request = usrInput.nextLine ( );
                // Request the file
                sendMessage ( request, sharedSecret );
                // Waits for the response
                processResponse ( RequestUtils.getFileNameFromRequest ( request) , sharedSecret );
            }
            // Close connection
            closeConnection ( );
        } catch ( IOException e ) {
            throw new RuntimeException ( e );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        // Close connection
        closeConnection ( );
    }

    /**
     * Reads the response from the server and writes the file to the temporary directory.
     *
     * @param fileName the name of the file to write
     */
    private void processResponse ( String fileName, BigInteger sharedSecret ) {
        try {
            Message response = ( Message ) in.readObject ( );
            byte[] decryptedMessage = Encryption.decryptMessage ( response.getMessage ( ) , sharedSecret.toByteArray ( ) );
            // Checks the HMAC of the message
            // Extracts the HMAC
            byte[] digest = response.getSignature ( );
            // Verifies the HMAC
            MessageDigest messageDigest = MessageDigest.getInstance ( "SHA-1" );
            //String hmacKey = "5v8y/B?E";
            byte[] result = HMAC.computeHMAC ( decryptedMessage , sharedSecret.toByteArray() , 64 , messageDigest );
            System.out.println ( "Message HMAC: " + new String ( result ) );

            if ( !Arrays.equals(result, digest)) {
                System.out.println ( "MAC verification failed" );
                closeConnection ( );
                return;
            }

            System.out.println ( "File received" );
            //String response = new String ( decryptedMessage );
            FileHandler.writeFile ( userDir + "/" + fileName , decryptedMessage);
        } catch (Exception e ) {
            e.printStackTrace ( );
        }
    }

    /**
     * Sends the path of the file to the server using the OutputStream of the socket. The message is sent as an object
     * of the {@link Message} class.
     *
     * @param filePath the message to send
     *
     * @throws IOException when an I/O error occurs when sending the message
     */
    public void sendMessage ( String filePath, BigInteger sharedSecret ) throws Exception {

        byte[] encryptedMessage = Encryption.encryptMessage ( filePath.getBytes ( ) , sharedSecret.toByteArray ( ) );
        // Computes the HMAC of the message
        MessageDigest messageDigest = MessageDigest.getInstance ( "SHA-1" );
        //String hmacKey = "5v8y/B?E";
        byte[] result = HMAC.computeHMAC ( filePath.getBytes ( ) , sharedSecret.toByteArray() , 64 , messageDigest );
        System.out.println ( "Message HMAC: " + new String ( result ) );
        // Creates the message object
        Message messageObj = new Message ( encryptedMessage, result);
        // Sends the encrypted message
        out.writeObject ( messageObj );

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
