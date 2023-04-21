import java.io.*;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class represents the file handler. It was the methods for reading and writing text files.
 */
public class FileHandler {


    static Map<String, Integer> userRequestCount = new HashMap<>();


    /**
     * Reads a text file and returns the result in bytes.
     *
     * @param path the path of the file to read
     *
     * @return the content of the file in bytes
     *
     * @throws IOException when an I/O error occurs when reading the file
     */
    public static byte[] readFile ( String path ) throws IOException {
        File file = new File ( path );
        byte[] fileBytes = new byte[ ( int ) file.length ( ) ];
        FileInputStream fileInputStream = new FileInputStream ( file );
        fileInputStream.read ( fileBytes );
        fileInputStream.close ( );
        return fileBytes;
    }

    /**
     * Writes a text file and returns the result in bytes
     */
    public static void writeFile ( String path , byte[] content ) throws IOException {
        File file = new File ( path );
        FileOutputStream fileOutputStream = new FileOutputStream ( file );
        fileOutputStream.write ( content );
        fileOutputStream.close ( );
    }



    static void readUserRequests() throws Exception {
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

    static void writeUserRequests(String username, int requestCount) throws IOException {
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
            userRequestCount.put(username, requestCount);
        }
        catch (IOException e) {
            System.err.println("Error writing user requests file: " + e.getMessage());
        }
    }





}
