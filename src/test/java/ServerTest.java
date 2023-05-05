import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.net.Socket;

import static org.junit.Assert.assertTrue;

public class ServerTest {
    private Server server;
    @Test
    @DisplayName("Server accepts client")
    public void testServerAcceptsClientConnection() throws Exception {
        server = new Server(8080);
        Thread thread = new Thread(server);
        thread.start();
        Socket client = new Socket("localhost", 8080);
        Thread.sleep(1000); // wait for server to process connection
        assertTrue(client.isConnected());
        client.close();
        server.closeConnection();
    }

    @Test
    @DisplayName("Server close connection")
    public void testServerClosesConnection() throws Exception {
        server = new Server(8080);
        Thread thread = new Thread(server);
        thread.start();
        server.closeConnection();
        assertTrue(server.server.isClosed());
        server.closeConnection();
    }

    @Test
    @DisplayName("Server is connected")
    public void testServerIsConnected() throws Exception {
        server = new Server(8080);
        Thread thread = new Thread(server);
        thread.start();
        assertTrue(server.isConnected);
        server.closeConnection();
    }

}