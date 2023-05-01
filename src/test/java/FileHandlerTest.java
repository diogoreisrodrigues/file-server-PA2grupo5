import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;


public class FileHandlerTest {

    private static final String FILE_PATH = "test.txt";
    private static final String TEST_CONTENT = "This is a test file.";

    @Test
    public void testReadFile() throws IOException {
        Path filePath = Paths.get(FILE_PATH);
        Files.write(filePath, TEST_CONTENT.getBytes());
        try {
            byte[] result = FileHandler.readFile(FILE_PATH);
            byte[] expected = TEST_CONTENT.getBytes();
            Assertions.assertArrayEquals(expected, result);
        } catch (IOException e) {
            fail("Unexpected exception: " + e.getMessage());
        }
        Files.deleteIfExists(filePath);
    }

    @Test
    public void testReadUserRequests() throws Exception {
        File file = new File("clientRequests.txt");
        List<String> lines = Arrays.asList("user1 10", "user2 5");
        Files.write(file.toPath(), lines);
        FileHandler.readUserRequests();
        Map<String, Integer> expected = new HashMap<>();
        expected.put("user1", 10);
        expected.put("user2", 5);
        assertEquals(expected, FileHandler.userRequestCount);
    }

    @Test
    public void testWriteFile() throws IOException {
        String path = "test.txt";
        String content = "Hello World!";
        byte[] bytes = content.getBytes();
        FileHandler.writeFile(path, bytes);
        byte[] result = FileHandler.readFile(path);
        assertEquals(content, new String(result));
        File file = new File(path);
        file.delete();
    }

    @Test
    public void testWriteUserRequests() throws IOException {
        FileHandler.writeUserRequests("Diogo",3);
        FileHandler.writeUserRequests("user1", 0);
        assertThrows(IOException.class, () -> FileHandler.writeUserRequests("Jotta", 0));

        //rever
    }

}