import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Chat {
    private final Socket socket;
    private final boolean client;
    private ObjectOutputStream netOut;
    private ObjectInputStream netIn;
    private Sender sender;
    private Receiver receiver;

    // Diffie-Hellman public parameters
    public static final BigInteger P = new BigInteger("150396459018121493735075635131373646237977288026821404984994763465102686660455819886399917636523660049699350363718764404398447335124832094110532711100861016024507364395416614225232899925070791132646368926029404477787316146244920422524801906553483223845626883475962886535263377830946785219701760352800897738687");
    public static final BigInteger G = new BigInteger("105003596169089394773278740673883282922302458450353634151991199816363405534040161825176553806702944696699090103171939463118920452576175890312021100994471453870037718208222180811650804379510819329594775775023182511986555583053247825364627124790486621568154018452705388790732042842238310957220975500918398046266");
    public static final int LENGTH = 1023;
    private byte[] key;

    public static void main(String[] args) throws IOException {
        Scanner in = new Scanner(System.in);
        System.out.println("Welcome to Secure Chat");
        System.out.println();

        boolean valid = false;

        try {
            do {
                System.out.print("Client or server? Enter c or s: ");
                String choice = in.nextLine();
                char letter = choice.toLowerCase().charAt(0);
                int port;

                if (letter == 's') {
                    System.out.print("Enter port number: ");
                    port = in.nextInt();
                    System.out.println("Waiting for client...");
                    new Chat(port);
                    valid = true;
                } else if (letter == 'c') {
                    System.out.println("Be sure to start server first!");
                    System.out.print("Enter IP address: ");
                    String IP = in.next();
                    System.out.print("Enter port number: ");
                    port = in.nextInt();
                    new Chat(IP, port);
                    valid = true;
                } else {
                    System.out.println("Invalid choice.");
                }
            } while (!valid);
        } catch (InterruptedException e) {
        }
    }

    // Server
    public Chat(int port) throws IOException, InterruptedException {
        client = false;
        ServerSocket serverSocket = new ServerSocket(port);
        socket = serverSocket.accept();
        runChat();
    }

    // Client
    public Chat(String address, int port) throws IOException, InterruptedException {
        client = true;
        socket = new Socket(address, port);
        runChat();
    }

    public void runChat() throws InterruptedException, IOException {
        netOut = new ObjectOutputStream(socket.getOutputStream());
        netIn = new ObjectInputStream(socket.getInputStream());

        System.out.println("Running chat ...");
        System.out.println();

        // Negotiates key using Diffie-Hellman
        Random random = new Random();
        BigInteger sameSecretKey;
        // creates key for client
        if (client) {
            BigInteger privateA = new BigInteger(LENGTH, random);
            BigInteger publicA = G.modPow(privateA, P);
            netOut.writeObject(publicA);
            netOut.flush();
            try {
                BigInteger publicB = (BigInteger) netIn.readObject();
                sameSecretKey = publicB.modPow(privateA, P);
                System.out.println("Client Secret Key: " + Arrays.toString(sameSecretKey.toByteArray()));
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }
        } else {
            // creates key for server
            BigInteger privateB = new BigInteger(LENGTH, random);
            BigInteger publicB = G.modPow(privateB, P);
            netOut.writeObject(publicB);

            try {
                BigInteger publicA = (BigInteger) netIn.readObject();
                sameSecretKey = publicA.modPow(privateB, P);
                System.out.println("Server Secret Key: " + Arrays.toString(sameSecretKey.toByteArray()));

            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
        key = sameSecretKey.toByteArray();

        sender = new Sender();
        receiver = new Receiver();
        sender.start();
        receiver.start();
        sender.join();
        receiver.join();
    }

    private class Sender extends Thread {
        public void run() {
            try {
                Scanner in = new Scanner(System.in);
                System.out.print("Enter your name: ");
                String name = in.nextLine();
                String buffer = "";
                while (!socket.isClosed()) {
                    buffer = in.nextLine();
                    if (buffer.trim().equalsIgnoreCase("quit")) {
                        return;
                    } else {
                        String line = name + ": " + buffer;
                        byte[] bytes = line.getBytes();
                        // creates copy of key
                        byte[] keyCopy = Arrays.copyOf(key, 16);
                        //calls encrypt to encrypt plaintext, and store in cipherBytes
                        byte[] cipherBytes = AES.encrypt(bytes, keyCopy);

                        netOut.writeObject(cipherBytes);
                        netOut.flush();
                    }
                }
            } catch (IOException e) {
            } finally {
                try {
                    netOut.close();
                    netIn.close();
                    socket.close();
                } catch (IOException e) {
                }
            }
        }
    }

    private class Receiver extends Thread {
        public void run() {
            try {
                while (!socket.isClosed()) {
                    byte[] bytes = (byte[]) (netIn.readObject());
                    // makes key copy
                    byte[] keyCopy = Arrays.copyOf(key, 16);
                    // decrypts encrypted byte array and stores it in decryptedBytes
                    byte[] decryptedBytes = AES.decrypt(bytes, keyCopy);
                    String line = new String(decryptedBytes);
                    System.out.println(line);
                }
            } catch (IOException e) {
            } catch (ClassNotFoundException e) { // Should never happen
                e.printStackTrace();
            } finally {
                try {
                    netOut.close();
                    netIn.close();
                    socket.close();
                } catch (IOException e) {
                }
                System.out.print("Connection closed.");
                // Bad programming style that would be unnecessary if this chat were in a GUI:
                System.exit(0);
            }
        }
    }
}