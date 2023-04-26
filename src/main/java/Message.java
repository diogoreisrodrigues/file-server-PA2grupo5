import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * This class represents a message object that is sent to the server by the client.
 */
public class Message implements Serializable {

    private final byte[] message;
    private final byte[] signature;
    private String username;

    /**
     * Constructs a Message object by specifying the message bytes that will be sent to the server.
     *
     * @param message the message that is sent to the server
     */
    public Message ( byte[] message, byte[] signature , String username) {
        this.message = message;
        this.signature = signature;
        this.username=username;
    }

    /**
     * Gets the message string.
     *
     * @return the message string
     */
    public byte[] getMessage ( ) {
        return message;
    }

    /**
     * Gets the signature of the message.
     *
     * @return the digest of the message
     */
    public byte[] getSignature ( ) {
        return signature;
    }

    /**
     * Converts the current object into a byte array representation
     *
     * @return the byte array representation of the current object
     *
     * @throws IOException if is an error writing to the output stream
     */
    public byte[] toBytes() throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);

        objectOutputStream.writeObject(this);
        objectOutputStream.flush();
        byte[] recordBytes = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();

        return recordBytes;
    }

    /**
     * Returns the username
     * @return the username
     */
    public String getUsername() {
        return username;
    }

}