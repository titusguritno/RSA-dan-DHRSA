
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A simple server socket listener that listens to port number 8888, and prints
 * whatever received to the console. It starts a thread for each connection to
 * perform IO operations.
 */
public class ThreadedSocketListener {

    ServerSocket server;
    int serverPort = 8888;
    private DHRSA dhrsa;

    // Constructor to allocate a ServerSocket listening at the given port.
    public ThreadedSocketListener() {
        try {
            dhrsa = new DHRSA();
            server = new ServerSocket(serverPort);
            System.out.println("ServerSocket: " + server);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Start listening.
    public void listen() {
        while (true) { // run until you terminate the program
            try {
                // Wait for connection. Block until a connection is made.
                Socket socket = server.accept();
                System.out.println("Socket: " + socket);
                // Start a new thread for each client to perform block-IO operations.
                new ClientThread(socket).start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        new ThreadedSocketListener().listen();
    }

    // Fork out a thread for each connected client to perform block-IO 
    class ClientThread extends Thread {

        Socket socket;
        DHRSA dhrsa;

        public ClientThread(Socket socket) {
            this.socket = socket;
            this.dhrsa = dhrsa;
        }

        @Override
        public void run() {
            try {
                InputStream iS = socket.getInputStream();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[3072];
                int bytesRead;
                while ((bytesRead = iS.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
                byte[] encryptedBytes = baos.toByteArray();
                String encryptedMessage = new String(encryptedBytes);

                // Decrypt the received message using DHRSA private key
                String decryptedMessage = dhrsa.decryptRSA(encryptedMessage);

                // Print the decrypted message
                System.out.println("Decrypted Message: " + decryptedMessage);

            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
