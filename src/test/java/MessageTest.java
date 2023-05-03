import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

public class MessageTest {
    @Test
    @DisplayName("Getters Test")
    public void testGetters() {
        byte[] message = "Hello user".getBytes();
        byte[] signature = "signature".getBytes();
        String username = "UserTest";
        Message msg = new Message(message, signature, username);

        assertAll("Getters",
                () -> assertArrayEquals(message, msg.getMessage()),
                () -> assertArrayEquals(signature, msg.getSignature()),
                () -> assertEquals(username, msg.getUsername())
        );
    }

    @Test
    @DisplayName("Method toBytes() Test")
    public void testToBytes() throws IOException, ClassNotFoundException {

        byte[] message = "Hello".getBytes();
        byte[] signature = "signature".getBytes();
        String username = "User";
        Message msg = new Message(message, signature, username);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(msg);
        objectOutputStream.flush();
        byte[] expectedBytes = byteArrayOutputStream.toByteArray();
        objectOutputStream.close();
        byteArrayOutputStream.close();

        byte[] actualBytes = msg.toBytes();
        assertArrayEquals(expectedBytes, actualBytes);
    }
}
