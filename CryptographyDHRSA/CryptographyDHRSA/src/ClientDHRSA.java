
import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.event.*;
import java.io.*;
import java.net.Socket;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import javax.swing.*;
import static javax.swing.JFrame.EXIT_ON_CLOSE;

public class ClientDHRSA extends JFrame implements ActionListener {

    private Socket client;
    private int serverPort = 54321;
//    private String serverAddr = "34.207.243.226"; // West Virginia
    private String serverAddr = "13.214.127.90"; // Singapore
    private PrintWriter out;
    private DHRSA dhrsa;
    private BigInteger sharedKey;
    private BigInteger modulus;
    private double totalLatency = 0;
    private int messageCount = 0;

    private JTextField tf;
    private JTextArea ta;
    private String encryptedResponse;
    private BigInteger publicKey;

    public ClientDHRSA() {
        // Set up the UI
        Container cp = this.getContentPane();
        cp.setLayout(new BorderLayout());

        ta = new JTextArea(10, 40);
        ta.setEditable(false);
        cp.add(new JScrollPane(ta), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new FlowLayout());

        tf = new JTextField(30);
        tf.addActionListener(this);
        bottomPanel.add(tf);

        JButton sendButton = new JButton("Send");
        sendButton.addActionListener(this);
        bottomPanel.add(sendButton);

        cp.add(bottomPanel, BorderLayout.SOUTH);

        this.setDefaultCloseOperation(EXIT_ON_CLOSE);
        this.pack();
        this.setTitle("Simple Client");
        this.setVisible(true);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() instanceof JTextField) {
            String message = tf.getText();
            if (message.equals("exit")) {
                // Need to close the socket to orderly disconnect from the server
                try {
                    out.close();
                    client.close();
                    System.exit(0);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            } else {
                try {
                    // Encrypt the message before sending it to the network socket
                    client = new Socket(serverAddr, serverPort);
                    System.out.println("Client: " + client);
                    out = new PrintWriter(client.getOutputStream(), true);
                    dhrsa = new DHRSA(); // Initialize RSA
                    String encryptedMessage = dhrsa.encryptRSA(message, dhrsa.getPublicKey());
                    System.out.println("Encrypted message : " + encryptedMessage);

                    double startTime = System.nanoTime(); // Start measuring latency
                    out.println(encryptedMessage); // Send the encrypted message to server
                    out.flush();
                    // Clear text field
                    tf.setText("");

                    // Receive response from server
                    BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
//                    System.out.println("test " + reader.readLine());
                    String encryptedResponse = reader.readLine(); // Read encrypted response from server
                    if (encryptedResponse != null) {
                        // Decrypt the response using RSA private key
                        String decryptedResponse = dhrsa.decryptRSA(encryptedMessage);

                        // Display the response
                        ta.append("Server(Encrypted) : " + encryptedResponse + "\n");
                        // Display the decrypted response
                        ta.append("Server : " + decryptedResponse + "\n");

                        double endTime = System.nanoTime(); // End measuring latency
                        double latency = (endTime - startTime) / 1000000; // Convert nano seconds to milliseconds
                        totalLatency += latency;
                        messageCount++;
                        // Display calculate latency
                        System.out.println("Startime = " + startTime);
                        System.out.println("Endtime = " + endTime);
                        System.out.println("Average Latency: " + (totalLatency / (double) messageCount) + " ms\n");
                        client.close();
                    }

                } catch (IOException ex) {
                    ex.printStackTrace();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) {
        // Start the client
        new ClientDHRSA();
    }
}
