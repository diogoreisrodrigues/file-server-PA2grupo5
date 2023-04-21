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

    /**
     * Constructs a Message object by specifying the message bytes that will be sent to the server.
     *
     * @param message the message that is sent to the server
     */
    public Message ( byte[] message, byte[] signature) {
        this.message = message;
        this.signature = signature;
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

    public byte[] toBytes() throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);

        objectOutputStream.writeObject(this);
        objectOutputStream.flush();
        byte[] recordBytes = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();

        return recordBytes;
    }
}