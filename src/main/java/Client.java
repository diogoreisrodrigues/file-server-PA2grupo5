import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.util.*;

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
    private static Map<String, Integer> userRequestCount = new HashMap<>();

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
        readUserRequests();
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

    private String askUsername() throws Exception {
        Scanner inputScanner = new Scanner(System.in);
        System.out.print("Enter your username: ");
        String newUsername = inputScanner.nextLine();
        if(userRequestCount.containsKey(newUsername)){
            System.out.print("Welcome back "+newUsername+" number of requests (after 5 requests new keys will be generated): "+userRequestCount.get(newUsername) + "\n");
        }
        else{
            System.out.println("New user on the system, adding to the file...");
            writeUserRequests(newUsername,0);
            System.out.println("Added with success!");
            readUserRequests();
        }
        return newUsername;
        //clientHandshake = new Handshake(newUsername, clientHandshake.encryptionAlgorithmType(), clientHandshake.encryptionAlgorithmName(), clientHandshake.encryptionKeySize(), clientHandshake.publicKey(), clientHandshake.encryptionAlgorithmName(), clientHandshake.blockSize());
    }


    /**
     * Executes the client. It reads the file from the console and sends it to the server. It waits for the response and
     * writes the file to the temporary directory.
     */
    public void execute ( BigInteger sharedSecret ) throws Exception {
        Scanner usrInput = new Scanner ( System.in );
        String userName= askUsername();
        int count= userRequestCount.get(userName);
        try {
            while ( isConnected ) {
                // Reads the message to extract the path of the file
                System.out.println ( "Write the path of the file" );
                String request = usrInput.nextLine ( );
                // Request the file
                sendMessage ( request, sharedSecret );
                // Waits for the response
                processResponse ( RequestUtils.getFileNameFromRequest ( request) , sharedSecret );
                if(count<5) {
                    count++;
                    writeUserRequests(userName,count);
                    userRequestCount.put(userName, count);
                    System.out.println("Number of current requests: "+count);
                }
                else{
                    count=0;
                    writeUserRequests(userName,0);
                    userRequestCount.put(userName, count);
                    //função de geração de novas chaves
                }
            }
            // Close connection
            closeConnection ( );
        } catch (Exception e ) {
            throw new RuntimeException ( e );
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
            String printedResponse = new String ( decryptedMessage );
            System.out.println("Content present on the file: "+ printedResponse);
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

    private static void readUserRequests() throws Exception {
        try (BufferedReader br= new BufferedReader(new FileReader("clientRequests.txt"))){
            String line;
            while((line=br.readLine())!=null){
                String[] separate = line.split(" ");
                if(separate.length == 2){
                    String username=separate[0];
                    int numRequests = Integer.parseInt(separate[1]);
                    userRequestCount.put(username,numRequests);
                }
            }
        }
        catch(IOException e){
            System.err.println("Error reading user requests file: "+e.getMessage());
        }
    }

    private static void writeUserRequests(String username, int requestCount) throws IOException {
        File file = new File("clientRequests.txt");
        boolean userExists = false;

        // Read the contents of the file
        List<String> lines = Files.readAllLines(file.toPath());

        // Loop through the lines and check if the user already exists
        for (int i = 0; i < lines.size(); i++) {
            String[] parts = lines.get(i).split(" ");
            if (parts[0].equals(username)) {
                lines.set(i, username + " " + requestCount);
                userExists = true;
                break;
            }
        }

        // If the user does not exist, append it to the end of the file
        if (!userExists) {
            lines.add(username + " " + requestCount);
        }

        // Write the updated contents back to the file
        try (FileWriter fw = new FileWriter(file)) {
            for (String line : lines) {
                fw.write(line + "\n");
            }
        }
        catch (IOException e) {
            System.err.println("Error writing user requests file: " + e.getMessage());
        }
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
