import org.junit.Test;
import static org.junit.Assert.*;

public class RequestUtilsTest {

    @Test
    public void testAbsoluteFilePath() {

        String request = "GET : hello.txt";
        String expectedPath = "server/files/hello.txt";
        String actualPath = RequestUtils.getAbsoluteFilePath(request);
        assertEquals(expectedPath, actualPath);

        String requestError="askforfile: nonexistentfile.txt";
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            RequestUtils.getAbsoluteFilePath(requestError);
        });
        assertEquals("Invalid request", exception.getMessage());

    }

    @Test
    public void testGetFileNameFromRequest() {

        String request = "GET : hello.txt";
        String expectedFileName = "hello.txt";
        String actualFileName = RequestUtils.getFileNameFromRequest(request);
        assertEquals(expectedFileName, actualFileName);

    }

}
