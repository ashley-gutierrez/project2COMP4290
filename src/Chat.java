import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Chat {
    private Socket socket;
    private boolean client;
    private ObjectOutputStream netOut;
    private ObjectInputStream netIn;
    private Sender sender;
    private Receiver receiver;

    // Diffie-Hellman public parameters
    public static final BigInteger P = new BigInteger("150396459018121493735075635131373646237977288026821404984994763465102686660455819886399917636523660049699350363718764404398447335124832094110532711100861016024507364395416614225232899925070791132646368926029404477787316146244920422524801906553483223845626883475962886535263377830946785219701760352800897738687");
    public static final BigInteger G = new BigInteger("105003596169089394773278740673883282922302458450353634151991199816363405534040161825176553806702944696699090103171939463118920452576175890312021100994471453870037718208222180811650804379510819329594775775023182511986555583053247825364627124790486621568154018452705388790732042842238310957220975500918398046266");
    public static final int LENGTH = 1023;
    private byte[] key;
    int[] sBox = {0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47, 0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,
            0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

    int[] rcon = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};

    public static void main(String[] args) throws UnknownHostException, IOException {
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
            } while( !valid );
        } catch(InterruptedException e) {}
    }

    // Server
    public Chat(int port) throws IOException, InterruptedException {
        client = false;
        ServerSocket serverSocket = new ServerSocket(port);
        socket = serverSocket.accept();
        runChat();
    }

    // Client
    public Chat(String address, int port) throws UnknownHostException, IOException, InterruptedException {
        client = true;
        socket = new Socket(address, port);
        runChat();
    }

    public void runChat() throws InterruptedException, IOException {
        netOut = new ObjectOutputStream(socket.getOutputStream());
        netIn = new ObjectInputStream(socket.getInputStream());

        System.out.println("Running chat ...");
        System.out.println();

        // TODO: Negotiate key using Diffie-Hellman here
        Random random = new Random();
        BigInteger sameSecretKey;
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
        }
        else {
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
        //System.out.println("Same Secret Key: " + Arrays.toString(key));

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
                    if (buffer.trim().toLowerCase().equals("quit")) {
                        return;
                    } else {
                        String line = name + ": " + buffer;
                        byte[] bytes = line.getBytes();
                        // TODO: Encrypt bytes here before sending them
                        byte[] keyCopy = Arrays.copyOf(key, 16);
                        System.out.println("Key copy:" + Arrays.toString(keyCopy));
                        /*byte[][] state = {{0x0, 0x4, 0x8, 0xC},
                                {0x1, 0x5, 0x9, 0xD},
                                {0x2, 0x6, 0xA, 0xE},
                                {0x3, 0x7, 0xB, 0xF}};
                         */

                        //BASED ON AES EXAMPLE
                        byte[] key = {0x54, 0x68, 0x61, 0x74,
                                0x73, 0x20, 0x6D, 0x79,
                                0x20, 0x4B, 0x75, 0x6E,
                                0x67, 0x20, 0x46, 0x75};
                        byte[] plaintext = {0x54, 0x77, 0x6F, 0x20,
                                0x4F, 0x6E, 0x65, 0x20,
                                0x4E, 0x69, 0x6E, 0x65,
                                0x20, 0x54, 0x77, 0x6F};

                        byte[][] ciphertext = encrypt(key, plaintext);
                        for (int i = 0; i < ciphertext.length; ++i) {
                            System.out.println(toHex(ciphertext[i]));
                        }

                        /* implemented in encrypt method
                        byte[][] roundKeys = new byte[11][16];
                        roundKeys[0] = key;
                        for(int i = 1; i <= roundKeys.length - 1; ++i) {
                            roundKeys[i] = getRoundKey(roundKeys[i - 1], i);
                        }

                        for(int i = 0; i < roundKeys.length; ++i) {
                            System.out.println("RoundKey " + i + ": " + toHex(roundKeys[i]));
                        }
                        byte[][] state = loadState(plaintext);
                        state = addRoundKey(state, roundKeys[0]);
                        System.out.println("New State matrix: ");
                        for (int i = 0; i < state.length; ++i) {
                            System.out.println(toHex(state[i]));
                        }
                        state = substitueBytes(state);
                        System.out.println("New State matrix after substitution: ");
                        for (int i = 0; i < state.length; ++i) {
                            System.out.println(toHex(state[i]));
                        }
                        state = shiftRows(state);
                        System.out.println("New State matrix after shift rows: ");
                        for (int i = 0; i < state.length; ++i) {
                            System.out.println(toHex(state[i]));
                        }
                        state = mixColumns(state);
                        System.out.println("New State matrix after mix column: ");
                        for (int i = 0; i < state.length; ++i) {
                            System.out.println(toHex(state[i]));
                        }
                         */


                        netOut.writeObject(bytes);
                        netOut.flush();
                    }
                }
            } catch (IOException e) {
            } finally {
                try {
                    netOut.close();
                    netIn.close();
                    socket.close();
                } catch( IOException e ) {}
            }
        }
    }
    private byte[] xorByteArrays (byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length];
        for (int i = 0; i < array1.length; ++i) {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }
        return result;
    }
    private String toHex(byte[] array) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < array.length; ++i) {
            hex.append(String.format("%02X ", array[i] & 0xFF));
        }
        return hex.toString();
    }
    private byte[] getRoundKey(byte[] previous, int round) {
        //splits key
        byte [] zero = Arrays.copyOfRange(previous, 0, 4);
        byte [] one = Arrays.copyOfRange(previous, 4, 8);
        byte [] two = Arrays.copyOfRange(previous, 8, 12);
        byte [] three = Arrays.copyOfRange(previous, 12, 16);
        //System.out.println("Last 4 Bytes: " + toHex(three));

        //left shift
        byte[] temp = Arrays.copyOf(three, 4);
        byte last = temp[0];
        for (int i = 0; i < temp.length - 1 ; ++ i) {
            temp [i] = temp[i+1];
        }
        temp[temp.length-1] = last;
        //System.out.println("Circular Left Shift: " + toHex(temp));

        //sBox and rcon
        for (int i = 0; i < temp.length; ++ i) {
            temp[i] = (byte) sBox[temp[i] & 0xFF];
        }
        //System.out.println("After S-box: " + toHex(temp));
        temp[0] ^= (byte) rcon[round];
        //System.out.println("After RCON: " + toHex(temp));

        //XOR
        byte[] four = xorByteArrays(zero, temp);
        byte[] five = xorByteArrays(four, one);
        byte[] six = xorByteArrays(five, two);
        byte[] seven = xorByteArrays(six, three);
        byte[] roundKey = new byte[16];
        System.arraycopy(four, 0, roundKey, 0,4);
        System.arraycopy(five, 0, roundKey, 4, 4);
        System.arraycopy(six, 0, roundKey, 8, 4);
        System.arraycopy(seven, 0, roundKey, 12, 4);
        //System.out.println("Roundkey: " + toHex(roundKey));
        return roundKey;
    }
    private byte[][] addRoundKey(byte[][] state, byte[] roundKey) {
        byte[][] newState = new byte[4][4];
        int index = 0;
        for(int column = 0; column < state.length; ++column) {
            for (int row = 0; row < state.length; ++row) {
                newState[row][column] = (byte) (state[row][column] ^ roundKey[index++]);
            }
        }
        return newState;
    }

    private byte[][] substituteBytes(byte[][] state) {
        byte[][] newState = new byte[4][4];
        for(int column = 0; column < state.length; ++column) {
            for (int row = 0; row < state.length; ++row) {
                newState[row][column] = (byte) sBox[state[row][column] & 0xFF];
            }
        }
        return newState;
    }

    private byte[][] shiftRows(byte[][] state) {
        byte[][] newState = new byte[4][4];
        for (int row = 0; row < state.length; ++row) {
            for(int column = 0; column < state.length; ++column) {
                newState[row][column] = state[row][(column + row) % state.length];
            }
        }
        return newState;
    }


    private  byte xTime(byte b) {
        return (byte) (((b & 0x80) != 0) ? ((b<<1) ^ 0x1B) : (b << 1));
    }

    private byte[][] mixColumns (byte[][] state) {
        byte[][] newState = new byte[4][4];
        for (int i = 0; i < state.length; ++i) {
            byte t = (byte) (state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i]);
            byte u = state[0][i];
            newState[0][i] = (byte) (state[0][i] ^ t ^ xTime((byte) (state[0][i] ^ state[1][i])));
            newState[1][i] = (byte) (state[1][i] ^ t ^ xTime((byte) (state[1][i] ^ state[2][i])));
            newState[2][i] = (byte) (state[2][i] ^ t ^ xTime((byte) (state[2][i] ^ state[3][i])));
            newState[3][i] = (byte) (state[3][i] ^ t ^ xTime((byte) (state[3][i] ^ u)));

            /* could be shorten with no newState?
            state[0][i] ^= (byte) (t ^ xtime((byte) (state[0][i] ^ state[1][i])));
            state[1][i] ^= (byte) (t ^ xtime((byte) (state[1][i] ^ state[2][i])));
            state[2][i] ^= (byte) (t ^ xtime((byte) (state[2][i] ^ state[3][i])));
            state[3][i] ^= (byte) (t ^ xtime((byte) (state[3][i] ^ u)));
             */
        }
        return newState;
    }
    private byte[][] loadState(byte[] plaintext) {
        byte[][] state = new byte[4][4];
        int index = 0;
        for(int column = 0; column < state.length; ++column) {
            for (int row = 0; row < state.length; ++row) {
                state[row][column] = plaintext[index++];
            }
        }
        return state;
    }

    private byte[][] encrypt(byte[] key, byte[] plaintext) {
        byte[][] state = loadState(plaintext);
        byte[][] roundKeys = new byte[11][16];
        roundKeys[0] = key;
        for (int i = 1; i <= roundKeys.length - 1; ++i) {
            roundKeys[i] = getRoundKey(roundKeys[i - 1], i);
        }
        //initial round
        state = addRoundKey(state, roundKeys[0]);
        //normal rounds 1-9
        for (int i = 1; i <=9; ++i){
            state = substituteBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, roundKeys[i]);
        }
        //final round
        state = substituteBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, roundKeys[10]);
        return state;
    }

    private class Receiver extends Thread {
        public void run() {
            try {
                while (!socket.isClosed()) {
                    byte[] bytes = (byte[])(netIn.readObject());
                    // TODO: Decrypt bytes here before reconstituting String
                    String line = new String(bytes);
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
                } catch( IOException e ) {}
                System.out.print("Connection closed.");
                // Bad programming style that would be unnecessary if this chat were in a GUI:
                System.exit(0);
            }
        }
    }
}