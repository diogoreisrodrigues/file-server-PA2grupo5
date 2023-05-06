import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class represents a server that receives a message from the clients. The server is implemented as a thread. Each
 * time a client connects to the server, a new thread is created to handle the communication with the client.
 */
public class Server implements Runnable {


    public static final String FILE_PATH = "server/files";
    final ServerSocket server;
    final boolean isConnected;

    private final PrivateKey privateRSAKey;
    private final PublicKey publicRSAKey;

    /**
     * Constructs a Server object by specifying the port number. The server will be then created on the specified port.
     * The server will be accepting connections from all local addresses.
     *
     * @param port the port number
     *
     * @throws IOException if an I/O error occurs when opening the socket
     */
    public Server ( int port ) throws Exception {
        server = new ServerSocket ( port );
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
        KeyPair keyPair = Encryption.generateKeyPair ( );
        this.privateRSAKey = keyPair.getPrivate ( );
        this.publicRSAKey = keyPair.getPublic ( );
    }

    /**

     This method runs the server thread. It listens for incoming connections and
     processes them by calling the process() method. The thread continues to run
     until the server is no longer connected.
     */
    @Override
    public void run ( ) {
        try {
            while ( isConnected ) {
                Socket client = server.accept ( );
                // Process the request
                process ( client );
            }
            closeConnection ( );
        } catch ( Exception e ) {
            throw new RuntimeException ( e );
        }
    }

    /**
     * Processes the request from the client.
     *
     * @throws IOException if an I/O error occurs when reading stream header
     */
    private void process ( Socket client ) throws Exception {
        ClientHandler clientHandler = new ClientHandler ( client, privateRSAKey, publicRSAKey);
        clientHandler.start ( );
    }

    /**
     * Closes the connection and the associated streams.
     */
    void closeConnection() {
        try {
            server.close ( );
        } catch ( IOException e ) {
            throw new RuntimeException ( e );
        }
    }

}