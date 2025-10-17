import java.util.Random;

public class BigInt implements Comparable<BigInt> {

         int sign;
        byte[] mag;
        final static int MAX =  Integer.MAX_VALUE / Integer.SIZE + 1; // (1 << 26)
    private static final long[] bitsPerDigit = { 0, 0,
            1024, 1624, 2048, 2378, 2648, 2875, 3072, 3247, 3402, 3543, 3672,
            3790, 3899, 4001, 4096, 4186, 4271, 4350, 4426, 4498, 4567, 4633,
            4696, 4756, 4814, 4870, 4923, 4975, 5025, 5074, 5120, 5166, 5210,
            5253, 5295};


    public BigInt(String value) {
        if (value.isEmpty()) {
            throw new NumberFormatException("Empty string");
        }

        int index = 0;//TODO

        if (value.charAt(0) == '0') {
            if (value.length() == 1) {
                this.sign = 0;
                this.mag = new byte[1];
            } else {
                this.sign = 1;
            }
        }
        while (value.length() > 1 && value.charAt(0) == '0') {
            value = value.substring(1);
        }
        int numOfDigits = value.length();

        long numBits = ((numOfDigits * bitsPerDigit[10]) >>> 10) + 1;

        int numWords = (int) (numBits + 31) >>> 5;
        int[] magnitude = new int[numWords];
    }
        private BigInt( int bitsSize, Random rnd){
            byte[] number = randomBits(bitsSize, rnd);

            if (number.length > 0) {
                sign = 1;
            } else {
                sign = 0;
            }
            if (number.length >= MAX) {
                // temp execption
            }
        }

        private byte[] randomBits ( int bits, Random rnd){
            int numBytes = (bits + 7) / 8;// + 7 to round up if bits not a multiple of 8
            byte[] randomBits = new byte[numBytes];

            rnd.nextBytes(randomBits);
            int excessBits = 8 * numBytes - bits;
            randomBits[0] &= (1 << (8 - excessBits)) - 1;//strip any extra bits
            return randomBits;
        }
        public BigInt( long val){
            if (val < 0) {
                val = -val;
                sign = -1;
            } else {
                sign = 1;
            }
            // TODO FIX INTO BYTES
            int high32 = (int) (val >>> 32);
            if (high32 == 0) {
                int[] number = new int[1];
                number[0] = (int) val;
            } else {
                int[] number = new int[2];
                number[0] = high32;
                number[1] = (int) val;
            }
        }

        @Override
        public int compareTo (BigInt o){
            return 0;
        }


    }
