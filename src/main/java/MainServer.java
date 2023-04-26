import java.io.IOException;

/**
 * Responsible for starting a new server and creating a new thread
 */
public class MainServer {

    /**
     * Main method to start the server
     *
     * @param args An array of String arguments passed to the program
     *
     * @throws IOException if is an I/O error while creating the server instance or starting the thread
     */
    public static void main ( String[] args ) throws IOException {
        Server server = new Server ( 8000 );
        Thread serverThread = new Thread ( server );
        serverThread.start ( );
    }

}
