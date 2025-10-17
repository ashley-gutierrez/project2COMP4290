import java.util.Arrays;
import static java.util.Arrays.copyOfRange;

/**
 * This class encrypts or decrypts an array of bytes using AES encryption using a 128-bit key on 128-bit blocks
 */
public class AES {
    private static final int[] sBox = {0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
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

    private static final int[] inverseBox = {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

    private static final int[] rcon = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
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


    /**
     * takes in the given plaintext byte array, and encrypts it 16 bytes(128bits) at a time,by calling the encryption method.
     * if the plaintext length is not a multiple of 8, it gets padded with zeros.
     * It then calls getByteArray on the encrypted block to turn it back into a byte array, and copies said byte array into cipherBytes.
     * @param plainText: a byte array
     * @param key a 128 bit byte array
     * @return an encrypted byte array
     */
    public static byte[] encrypt(byte[] plainText, byte[] key){
        byte[][] ciphertext;
        byte [] cipherBytes = new byte[plainText.length + (16 - (plainText.length %16) ) ];
        for (int i = 0; i < cipherBytes.length; i +=16) {
            ciphertext = encryption(key, copyOfRange(plainText,i,i+16));
            System.arraycopy(getByteArray(ciphertext),0,cipherBytes,i,16);
        }
        return cipherBytes;
    }
    /**
     * takes in the given AES encrypted byte array, and decrypts it 16 bytes(128bits) at a time,by calling the decryption method
     * It then calls getByteArray on the decrypted block to turn it back into a byte array, and copies said byte array into decryptedBytes.
     * Lastly it removes any zeros that were used to pad the byte array while encrypting it
     * @param cipherBytes: an AES encrypted byte array
     * @param key a 128 bit byte array key
     * @return a decrypted byte array
     */
    public static byte[] decrypt(byte[] cipherBytes, byte[] key){
        byte[][] decryptedText;
        byte[] decryptedBytes = new byte[cipherBytes.length ];
        for (int i = 0; i < decryptedBytes.length; i+= 16) {
            decryptedText = decryption(key, copyOfRange(cipherBytes,i,i+16));
            System.arraycopy(getByteArray(decryptedText),0,decryptedBytes,i,16);
        }
        int lastIndex =0;
        while (lastIndex != -1) {
            if (decryptedBytes[lastIndex] == 0){
                decryptedBytes = copyOfRange(decryptedBytes,0,lastIndex);
                lastIndex = -2;
            }
            lastIndex++;
        }
        return decryptedBytes;
    }

    /**
     * it XORs the bytes at the same index of two byte arrays of the same length
     * @param array1 a byte array of the same length as array2
     * @param array2  a byte array of the same length as array1
     * @return a byte array or the XORed bytes of arrays 1 and 2
     */
    private static byte[] xorByteArrays (byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length];
        for (int i = 0; i < array1.length; ++i) {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }
        return result;
    }

    /**
     * it converts a 2d array in [column][row] format into a single byte array
     * @param state a 2d array of bytes
     * @return a flattened 2d array into a single byte array
     */
    private static byte[] getByteArray(byte[][] state) {
        byte[] array = new byte[state.length * state.length];
        int index = 0;
        for (int column = 0; column < state.length; ++column) {
            for (int row = 0; row < state.length; ++row) {
                array[index++] = state[row][column];
            }
        }
        return array;
    }

    /**
     *  it generates the key of the current round of the AES algorithm by running the last key through the key schedule core in 4 byte chunks.
     *  then XORing the key schedule core 4 byte chunks with the corresponding 4 bytes from the previous round key
     *  These 4 bytes become the next 4 bytes of the current round key.
     * @param previous a byte array containing the previous round key in the AES algorithm
     * @param round an int, the round the AES algorithm is on
     * @return the key of the current round in the  AES algorithm
     */
    private static byte[] getRoundKey(byte[] previous, int round) {
        //splits key
        byte [] zero = copyOfRange(previous, 0, 4);
        byte [] one = copyOfRange(previous, 4, 8);
        byte [] two = copyOfRange(previous, 8, 12);
        byte [] three = copyOfRange(previous, 12, 16);

        //left shift
        byte[] temp = Arrays.copyOf(three, 4);
        byte last = temp[0];
        for (int i = 0; i < temp.length - 1 ; ++ i) {
            temp [i] = temp[i+1];
        }
        temp[temp.length-1] = last;

        //sBox and rcon
        for (int i = 0; i < temp.length; ++ i) {
            temp[i] = (byte) sBox[temp[i] & 0xFF];
        }
        temp[0] ^= (byte) rcon[round];

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
        return roundKey;
    }

    /**
     * it XORs the corresponding byte in the state with the next byte in the round key
     * the state is XORed column by column
     * @param state a 2d array that hold the data that is being encrypted
     * @param roundKey the current round key of the AES algorithm
     */
    private static void addRoundKey(byte[][] state, byte[] roundKey) {
        int index = 0;
        for(int column = 0; column < state.length; ++column) {
            for (int row = 0; row < state.length; ++row) {
                state[row][column] ^= roundKey[index++];
            }
        }
    }

    /**
     * this method substitutes the bytes in the state with bytes from the S-Box
     * @param state a 2d array that hold the data that is being encrypted
     */
    private static void substituteBytes(byte[][] state) {
        for(int row = 0; row < state.length; ++row) {
            for (int column = 0; column < state.length; ++column) {
                state[row][column] = (byte) sBox[state[row][column] & 0xFF];
            }
        }
    }
    /**
     * this method rotates the rows in a specific way.
     * Row 0 is rotated to the left 0 bytes, Row 1 is rotated to the left 1 byte, Row 2 is rotated to the left 2 bytes, Row 3 is rotated to the left 3 bytes.
     * @param state a 2d array that hold the data that is being encrypted
     */
    private static void shiftRows(byte[][] state) {
        for (int row = 1; row < state.length; ++row) {
            byte[] temp = new byte[state.length];
            for(int column = 0; column < state.length; ++column) {
                temp[column] = state[row][(column + row) % state.length];
            }
            System.arraycopy(temp, 0, state[row], 0, state.length);
        }
    }
    /**
     * this method combines the columns with themselves.
     *
     * @param state a 2d array that hold the data that is being encrypted
     */
    private static void mixColumns(byte[][] state) {
        byte[] a = new byte[4];
        for (int j = 0; j < state.length; ++j) {
            for (int i = 0; i < state.length; ++i)
                a[i] = state[i][j];

            state[0][j] = (byte) (galoisMultiply(a[0],2) ^ galoisMultiply(a[1],3) ^ a[2] ^ a[3]);
            state[1][j] = (byte) (a[0] ^ galoisMultiply(a[1],2) ^ galoisMultiply(a[2],3) ^ a[3]);
            state[2][j] = (byte) (a[0] ^ a[1] ^ galoisMultiply(a[2],2) ^ galoisMultiply(a[3],3));
            state[3][j] = (byte) (galoisMultiply(a[0],3) ^ a[1] ^ a[2] ^ galoisMultiply(a[3],2));
        }
    }

    private static void inverseMixColumns(byte[][] state) {
        byte[] a = new byte[4];
        for (int j = 0; j < state.length; ++j) {
            for (int i = 0; i < state.length; ++i)
                a[i] = state[i][j];

            state[0][j] = (byte) (galoisMultiply(a[0],14) ^ galoisMultiply(a[3],9) ^ galoisMultiply(a[2],13) ^ galoisMultiply(a[1],11));
            state[1][j] = (byte) (galoisMultiply(a[1],14) ^ galoisMultiply(a[0],9) ^ galoisMultiply(a[3],13) ^ galoisMultiply(a[2],11));
            state[2][j] = (byte) (galoisMultiply(a[2],14) ^ galoisMultiply(a[1],9) ^ galoisMultiply(a[0],13) ^ galoisMultiply(a[3],11));
            state[3][j] = (byte) (galoisMultiply(a[3],14) ^ galoisMultiply(a[2],9) ^ galoisMultiply(a[1],13) ^ galoisMultiply(a[0],11));
        }
    }

    private static byte galoisMultiply(int a, int b) {
        int p = 0;
        int highBit;

        for (int i = 0; i < 8; ++i) {
            if ((b & 1) == 1)
                p ^= a;
            highBit = a & 0x80;
            a <<= 1;
            if (highBit == 0x80)
                a ^= 0x1b;
            b >>= 1;
        }

        p &= 0xff;

        return (byte)p;
    }

    /**
     *
     * @param plaintext
     * @return
     */
    private static byte[][] loadState(byte[] plaintext) {
        byte[][] state = new byte[4][4];
        int index = 0;
        for(int column = 0; column < state.length; ++column) {
            for (int row = 0; row < state.length; ++row) {
                state[row][column] = plaintext[index++];
            }
        }
        return state;
    }

    /**
     *
     * @param key
     * @param plaintext
     * @return
     */
    private static byte[][] encryption(byte[] key, byte[] plaintext) {
        byte[][] state = loadState(plaintext);
        byte[][] roundKeys = new byte[11][16];
        roundKeys[0] = key;
        for (int i = 1; i <= roundKeys.length - 1; ++i) {
            roundKeys[i] = getRoundKey(roundKeys[i - 1], i);
        }
        //initial round
        addRoundKey(state, roundKeys[0]);
        //normal rounds 1-9
        for (int i = 1; i <=9; ++i){
            substituteBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[i]);
        }
        //final round
        substituteBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[10]);
        return state;
    }

    /**
     *
     * @param key
     * @param ciphertext
     * @return
     */
    private static byte[][] decryption(byte[] key, byte[] ciphertext) {
        byte[][] state = loadState(ciphertext);
        byte[][] roundKeys = new byte[11][16];
        roundKeys[0] = key;
        for (int i = 1; i <= roundKeys.length - 1; ++i) {
            roundKeys[i] = getRoundKey(roundKeys[i - 1], i);
        }
        //inverse final round
        addRoundKey(state, roundKeys[10]);
        inverseShiftRows(state);
        inverseSubstituteBytes(state);

        //inverse normal rounds 9-1
        for (int i = 9; i >= 1; --i){
            addRoundKey(state, roundKeys[i]);
            inverseMixColumns(state);
            inverseShiftRows(state);
            inverseSubstituteBytes(state);
        }
        //inverse initial round
        addRoundKey(state, roundKeys[0]);

        return state;
    }

    /**
     *
     * @param state
     */
    private static void inverseShiftRows(byte[][] state) {
        for (int row = 0; row < state.length; ++row) {
            byte[] temp = new byte[state.length];
            for(int column = 0; column < state.length; ++column) {
                temp[column] = state[row][(column - row + state.length) % state.length];
            }
            System.arraycopy(temp, 0, state[row], 0, state.length);
        }
    }

    /**
     *
     * @param state
     */
    private static void inverseSubstituteBytes(byte[][] state) {
        for (int row = 0; row < state.length; ++row) {
            for(int column = 0; column < state.length; ++column) {
                state[row][column] = (byte) inverseBox[state[row][column] & 0xFF];
            }
        }
    }
}
