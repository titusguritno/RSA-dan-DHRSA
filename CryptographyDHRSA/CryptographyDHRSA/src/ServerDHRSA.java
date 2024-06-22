
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ServerDHRSA {

    private ServerSocket server;
    private int serverPort = 12345;
    private DHRSA dhrsa;
    private BigInteger sharedKey;
    private BigInteger modulus;
    private double totalLatency = 0;
    private int messageCount = 0;

    public ServerDHRSA() {
        try {
            server = new ServerSocket(serverPort);
            System.out.println("ServerSocket: " + server);
            dhrsa = new DHRSA(); // Initialize RSA
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void listen() {
        while (true) { // run until you terminate the program
            try {
                // Wait for connection. Block until a connection is made.
                Socket socket = server.accept();
                System.out.println("Socket: " + socket);

                // Read encrypted message from client
                double startTime = System.nanoTime(); // Start measuring latency
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String encryptedMessage = reader.readLine();
                double endTime = System.nanoTime(); // End measuring latency

                // Decrypt the received message using RSA private key
                String decryptedMessage = dhrsa.decryptRSA(encryptedMessage);

                // Print the decrypted message
                System.out.println("Decrypted Message: " + decryptedMessage);

                // Respond to the client
                OutputStream outputStream = socket.getOutputStream();
                PrintWriter writer = new PrintWriter(outputStream, true);
                String response = "Server received : " + decryptedMessage;

                // Encrypt the response before sending it back to the client
                String encryptedResponse = dhrsa.encryptRSA(response, dhrsa.getPublicKey());
                writer.println(encryptedResponse);
                writer.flush();

            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public double getTotalLatency() {
        return totalLatency;
    }

    public int getMessageCount() {
        return messageCount;
    }

    public static void main(String[] args) {
        new ServerDHRSA().listen();
        // Start the server and listening
    }
}
