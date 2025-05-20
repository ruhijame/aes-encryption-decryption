/**
 * Overview:
 *      This program is an AES encryption and decryption program. It encrypts and decrypts in ECB and CBC modes.
 * 
 * How To Run:
 *      Run java AES.java in the terminal
 *      Follow intructions to choose whether to encrypt or decrypt, decide mode, and entering filename and key filename
 * 
 * Providing Input:
 *      FILES:
 *          Provide the file names for the files you want to encrypt or decrypt. You do not need to add quotation marks or any other 
 *          additional characters. Include the file name extension and make sure the file in the same directory that this program is in.
 * 
 *          Example from program:
 *              Enter filename: aes-plaintext1.txt
 *              Enter key filename: aes-key1.txt
 *     MODES:
 *          The program asks in the terminal what mode you want to use. Type the number corresponding to the mode that you want to use.
 *          
 *          Example from program:
 *              What mode? Enter the number corresponding to your choice.
 *              0: ECB
 *              1: CBC
 *              1
 *          
 *          In the example, the user inputted 1, so the program will use CBC.
 * 
 * Notes:
 *      Make sure the filenames are exact as there is no file handling for incorrect filenames
 *      For "Enter filename", enter the file name for the ciphertext or the plaintext
 *      For "Enter key filename", enter the file name for the key
 *      Make sure to include the correct key file for the plaintext or ciphertext file
 */


import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class AES {

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        // encrypt or decrypt?
        System.out.println("What do you want to do? Enter the number corresponding to your choice.");
        System.out.println("0: Encrypt");
        System.out.println("1: Decrypt");

        int cryption = scanner.nextInt();
        scanner.nextLine();

        // mode?
        System.out.println("What mode? Enter the number corresponding to your choice.");
        System.out.println("0: ECB");
        System.out.println("1: CBC");

        int mode = scanner.nextInt();
        scanner.nextLine();

        // input plaintext or ciphertext filename
        System.out.print("Enter filename: ");
        
        String filename = "test_file/" + scanner.nextLine();

        // input key filename
        System.out.print("Enter key filename: ");

        String keyFile = "test_file/" + scanner.nextLine();

        String keyHexString = ""; 
        String textHexString = "";

        try {
            // reading file contents into a string
            textHexString = readFileToString(filename);
            keyHexString = readFileToString(keyFile);

        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }

        // turning the string into an array
        byte[] text = hexStringToByteArray(textHexString);
        byte[] key = hexStringToByteArray(keyHexString);

        // making sure the byte arrays are not null
        if (text == null || key == null) {
            System.out.println("plaintext array or key array are null");
            return;
        }

        byte[] outputBytes = null;

        // encrypt or decrypt based on user's choice
        if (cryption == 0) {
            System.out.println("Encrypting...");

            // calling the encryption methods based on mode
            if (mode == 0) {
                outputBytes = encryptECB(text, key);
            }
            else if (mode == 1) {
                outputBytes = encryptCBC(text, key);
            }
            else {
                System.out.println(mode + " not a valid mode");
                return;
            }
        }
        else if (cryption == 1) {
            System.out.println("Decrypting...");

            // calling the decryption methods based on mode
            if (mode == 0) {
                outputBytes = decryptECB(text, key);
            }
            else if (mode == 1) {
                outputBytes = decryptCBC(text, key);
            }
            else {
                System.out.println(mode + " not a valid mode");
                return;
            }
        }
        else {
            System.out.println(cryption + " invalid choice.");
            return;
        }

        // checking if the operation was completed, then printing out the string
        if (outputBytes != null) {
            System.out.println("Operation completed successfully!");
            System.out.println("Output: " + bytesToHex(outputBytes));
        }
        else {
            System.out.println("An error occurred during encryption/decryption");
        }

    }


    /* Decryption Functions */

    /**
     * Decryption using ECB mode
     * 
     * @param inputBytes - byte array to decrypt
     * @param keyBytes - byte array with the key for decryption
     * 
     * @return returns a byte array with the decrypted message
     */
    public static byte[] decryptECB(byte[] inputBytes, byte[] keyBytes) {
        // creating new array to hold decrypted bytes
        byte[] output = new byte[inputBytes.length];

        // splitting the inputBytes into 128 bit blocks
        int numBlocks = inputBytes.length / 16;

        // expanding the key
        byte[] expandedKey = expandKey(keyBytes);

        // looping through the blocks
        for (int i = numBlocks - 1; i >= 0; i--) {
            // decrypting each individual block
            int offset = i * 16;
            byte[] block = Arrays.copyOfRange(inputBytes, offset, offset + 16);
            byte[] decryptedBlock = decryptBlock(block, expandedKey);
            
            // copying block to the output array
            System.arraycopy(decryptedBlock, 0, output, offset, 16);
        }

        // returning decrypted byte array
        return output;
    }

    /**
     * Decryption using CBC mode
     * 
     * @param inputBytes - byte array to decrypt
     * @param keyBytes - byte array with the key for decryption
     * 
     * @return returns a byte array with the decrypted message
     */
    public static byte[] decryptCBC(byte[] inputBytes, byte[] keyBytes) {
        // expanding the key array
        byte[] expandedKey = expandKey(keyBytes);

        // if inputBytes is 16 elements, then doing normal decryption
        if (inputBytes.length == 16) {
            byte[] regOutput = decryptBlock(inputBytes, expandedKey);
            return regOutput;
        }

        // setting up the required array
        byte[] output = new byte[inputBytes.length];
        byte[] prev = new byte[16]; 

        // decrypting using the CBC method
        for (int i = 0; i < inputBytes.length; i += 16) {

            // getting individual 128-bit blocks of inputBytes
            byte[] block = Arrays.copyOfRange(inputBytes, i, i + 16);

            // decrypting the block
            byte[] decrypted = decryptBlock(block, expandedKey);

            // xor decrypted block with the ciphertext from the previous round
            byte[] xored = xorBlocks(decrypted, prev);

            // copying to the output array
            System.arraycopy(xored, 0, output, i, 16);

            // setting prev to the previous block for the next round
            prev = block;
        }

        // returning the decrypted byte array
        return output;
    }

    /**
     * Decrypting one block of 128 bits
     * 
     * @param input - byte array of 128 bits to decrypt
     * @param expandedKey - byte array of the expanded key
     * 
     * @return returns a byte array with the 128-bit message decrypted
     * 
     * @throws IllegalArgumentException - expanded key length is not of correct length
     */
    public static byte[] decryptBlock(byte[] input, byte[] expandedKey) {
        int totalRounds = 0;

        // assigning rounds depending on key length
        switch (expandedKey.length) {
            case 176: 
                totalRounds = 10; 
                break;
            case 216: 
                totalRounds = 12; 
                break;
            case 256: 
                totalRounds = 14; 
                break;
            default: 
                throw new IllegalArgumentException("Invalid expanded key length: " + expandedKey.length);
        }

        // creating new array to make changes to
        byte[] state = input.clone();

        // initial round of decryption
        state = addRoundKey(state, expandedKey, totalRounds);

        // middle rounds of decryption
        for (int round = totalRounds - 1; round > 0; round--) {
            state = invShiftRows(state);
            state = invSubBytes(state);
            state = addRoundKey(state, expandedKey, round);
            state = invMixColumns(state);
        }

        // final round
        state = invShiftRows(state);
        state = invSubBytes(state);
        state = addRoundKey(state, expandedKey, 0);

        // returns byte array with decrypted block
        return state;
    }

    /**
     * Substitutes bytes based on the inverse s-box
     * 
     * @param b - byte to be substituted
     * 
     * @return returns the substituted byte
     */
    public static byte invSubBytes(byte b) {
        // using the invSbox to find the inverse substitution
        return AESConstants.invSbox[b & 0xFF];
    }

    /**
     * Substitutes an array of bytes based on the inverse s-box
     * 
     * @param state - array of bytes to be substituted
     * 
     * @return returns an array where all the bytes were substituted
     */
    public static byte[] invSubBytes(byte[] state) {
        // creating a new array to hold the substituted bytes
        byte[] result = new byte[16];

        // looping through the array and substituting each byte
        for (int i = 0; i < 16; i++) {
            // using the invSubBytes method to substitute each byte
            result[i] = invSubBytes(state[i]);
        }

        // return the array with the substituted bytes
        return result;
    }

    /**
     * Shifts the rows to the right (inverse of shiftRows)
     * 
     * @param currentState - byte array representing the current state of the bytes
     * 
     * @return returns the byte array with the rows shifted
     */
    public static byte[] invShiftRows(byte[] currentState) {
        // creating a new array to hold the shifted bytes
        byte[] result = new byte[16];

        // row 1 - no shift
        result[0] = currentState[0];
        result[4] = currentState[4];
        result[8] = currentState[8];
        result[12] = currentState[12];

        // row 2 - shift 1 to the right
        result[1] = currentState[13];
        result[5] = currentState[1];
        result[9] = currentState[5];
        result[13] = currentState[9];

        // row 3 - shift 2 to the right
        result[2] = currentState[10];
        result[6] = currentState[14];
        result[10] = currentState[2];
        result[14] = currentState[6];

        // row 4 - shift 3 to the right
        result[3] = currentState[7];
        result[7] = currentState[11];
        result[11] = currentState[15];
        result[15] = currentState[3];

        // return the array with the bytes shifted
        return result;
    }

    /**
     * Multiplying by 9 in the AES field
     * 
     * @param b - byte that is being multiplied
     * 
     * @return returns the resultant byte after the operation
     */
    public static byte mulBy9(byte b) {
        // using xtimes function to perform the operation and returning the resultant byte
        return (byte) (xtimes(xtimes(xtimes(b))) ^ b);
    }

    /**
     * Multiplying by 11 in the AES field
     * 
     * @param b - byte that is being multiplied
     * 
     * @return returns the resultant byte after the operation
     */
    public static byte mulBy11(byte b) {
        // using the xtimes function to perform the operation
        byte temp1 = xtimes(b);
        byte temp2 = xtimes(xtimes(temp1));

        // return the resultant byte
        return (byte) (temp2 ^ temp1 ^ b);
    }

    /**
     * Multiplying by 13 in the AES field
     * 
     * @param b - byte that is being multiplied
     * 
     * @return returns the resultant byte after the operation
     */
    public static byte mulBy13(byte b) {
        // using the xtimes function to perform the operation
        byte temp1 = xtimes(xtimes(b));  
        byte temp2 = xtimes(temp1);  

        // returning the resultant byte
        return (byte) (temp2 ^ temp1 ^ b);
    }

    /**
     * Multiplying by 14 in the AES field
     * 
     * @param b - byte that is being multiplied
     * 
     * @return returns the resultant byte after the operation
     */
    public static byte mulBy14(byte b) {
        // using the xtimes function to perform the operation
        byte temp1 = xtimes(b);  
        byte temp2 = xtimes(temp1);  
        byte temp3 = xtimes(temp2);  

        // returning the resultant byte
        return (byte) (temp3 ^ temp2 ^ temp1);
    }

    /**
     * Performs the inverse of the mixColumns function
     * 
     * @param state - byte array representing the current state of the bytes
     * 
     * @return returns a byte array after the inverse mix columns function is completed
     */
    public static byte[] invMixColumns(byte[] state) {
        // creating a new array to hold the resultant array of bytes
        byte[] result = new byte[16];

        // looping through each column
        for (int c = 0; c < 4; c++) {
            int i = c * 4;

            // finding the bytes in the current column
            byte s0 = state[i];
            byte s1 = state[i + 1];
            byte s2 = state[i + 2];
            byte s3 = state[i + 3];

            // performing the multiplication to each byte in the column
            result[i] = (byte) (mulBy14(s0) ^ mulBy11(s1) ^ mulBy13(s2) ^ mulBy9(s3));
            result[i + 1] = (byte) (mulBy9(s0)  ^ mulBy14(s1) ^ mulBy11(s2) ^ mulBy13(s3));
            result[i + 2] = (byte) (mulBy13(s0) ^ mulBy9(s1)  ^ mulBy14(s2) ^ mulBy11(s3));
            result[i + 3] = (byte) (mulBy11(s0) ^ mulBy13(s1) ^ mulBy9(s2)  ^ mulBy14(s3));
        }

        // returning the resultant array of bytes
        return result;
    }


    /* Encryption Functions */

    /**
     * Encryption using ECB mode
     * 
     * @param inputBytes - byte array to decrypt
     * @param keyBytes - byte array with the key for encryption
     * 
     * @return returns a byte array with the encrypted message
     */
    public static byte[] encryptECB(byte[] inputBytes, byte[] keyBytes) {
        // creating a new array to hold the encrypted bytes
        byte[] output = new byte[inputBytes.length];

        // splitting the inputBytes into 128-bit blocks
        int numBlocks = inputBytes.length / 16;

        // expanding the key
        byte[] expandedKey = expandKey(keyBytes);

        // looping through the blocks
        for (int i = 0; i < numBlocks; i++) {
            // encrypting each individual block
            int offset = i * 16;
            byte[] block = Arrays.copyOfRange(inputBytes, offset, offset + 16);
            byte[] encryptedBlock = encryptBlock(block, expandedKey);

            // copying block to the output array
            System.arraycopy(encryptedBlock, 0, output, offset, 16);
        }

        // returning encrypted byte array
        return output;
    }

    /**
     * Encryption using CBC mode
     * 
     * @param inputBytes - byte array to encrypt
     * @param keyBytes - byte array with the key for encryption
     * 
     * @return returns a byte array with the encrypted message
     */
    public static byte[] encryptCBC(byte[] inputBytes, byte[] keyBytes) {
        // expanding the key array
        byte[] expandedKey = expandKey(keyBytes);

        // if inputBytes is 16 elements, then doing normal encryption
        if (inputBytes.length == 16) {
            byte[] regOutput = encryptBlock(inputBytes, expandedKey);
            return regOutput;
        }

        // setting up the required arrays
        byte[] output = new byte[inputBytes.length];
        byte[] prev = new byte[16]; 

        // encrypting using the CBC method
        for (int i = 0; i < inputBytes.length; i += 16) {

            // getting individual 128-bit blocks of inputBytes
            byte[] block = Arrays.copyOfRange(inputBytes, i, i + 16);

            // xor block with the previous block
            byte[] xored = xorBlocks(block, prev);

            // encrypting the xored block
            byte[] encrypted = encryptBlock(xored, expandedKey);

            // copying to the output array
            System.arraycopy(encrypted, 0, output, i, 16);

            // setting prev to the newly encrypted block
            prev = encrypted;
        }

        // returning the encrypted byte array
        return output;
    }

    /**
     * Encrypting one block of 128-bits
     * 
     * @param input - byte array of 128 bits of encrypt
     * @param expandedKey - byte array of the expanded key
     * 
     * @return returns a byte array with the 128-bit message encrypted
     */
    public static byte[] encryptBlock(byte[] input, byte[] expandedKey) {
        int totalRounds = 0;

        switch (expandedKey.length) {
            case 176: 
                totalRounds = 10; 
                break; 
            case 216: 
                totalRounds = 12; 
                break; 
            case 256: 
                totalRounds = 14; 
                break;
            default: 
                throw new IllegalArgumentException("Invalid expanded key length: " + expandedKey.length);
        }

        // creating new array to make changes to input array
        byte[] state = input.clone();

        // initial round of encryption
        state = addRoundKey(state, expandedKey, 0);

        // middle rounds of encryption
        for (int round = 1; round < totalRounds; round++) {
            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, expandedKey, round);
        }

        // final round of encryption
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, expandedKey, totalRounds);

        // returns byte array with encrypted block
        return state;
    }

    /**
     * Calls the correct key expansion method depending on the length of the key byte array
     * 
     * @param keyBytes - byte array of the key
     * 
     * @return returns the byte array of the expanded key
     */
    private static byte[] expandKey(byte[] keyBytes) {
        // calling the key expansion method depending on the length of the key array
        switch (keyBytes.length) {
            case 16:
                return keyExpansion128(keyBytes);
            case 24:
                return keyExpansion192(keyBytes);
            case 32:
                return keyExpansion256(keyBytes);
            default:
                throw new IllegalArgumentException("Invalid AES key length: " + keyBytes.length);
        }
    }

    /**
     * XORing each element of a byte array
     * 
     * @param a - one byte array
     * @param b - one byte array
     * 
     * @return returns a byte array with the elements of the a xor b
     */
    private static byte[] xorBlocks(byte[] a, byte[] b) {
        // creating new array to store xor elements
        byte[] result = new byte[16];

        // looping through one array - assuming arrays are of equal length
        for (int i = 0; i < 16; i++) {
            // xor the elements
            result[i] = (byte) (a[i] ^ b[i]);
        }

        // returns the resultant byte array
        return result;
    }

    /**
     * Generates a different 128-bit key for each round
     * 
     * @param text - byte array for the plaintext or ciphertext
     * @param expandedKey - byte array for the expanded key
     * @param round - the current round number
     */
    public static byte[] addRoundKey(byte[] text, byte[] expandedKey, int round) {
        // creating a new array for the round key bytes
        byte[] result = new byte[16];

        // calculates the starting index for the round's key
        int offset = round * 16;

        // loops through the result byte array
        for (int i = 0; i < 16; i++) {
            // xor the current text byte and the current expandedKey byte
            result[i] = (byte) (text[i] ^ expandedKey[i + offset]);
        }

        // returns the resulant byte array
        return result;
    }

    /**
     * Shifts rows to the left
     * 
     * @param currentState - current state of the byte array
     * 
     * @return returns a byte array with the bytes shifted to the left
     */
    public static byte[] shiftRows(byte[] currentState) {
        // creating a new array to hold the shifted bytes
        byte[] result = new byte[16];

        // row 1 - no shift
        result[0] = currentState[0];
        result[4] = currentState[4];
        result[8] = currentState[8];
        result[12] = currentState[12];

        // row 2 - shift 1 to the left
        result[1] = currentState[5];
        result[5] = currentState[9];
        result[9] = currentState[13];
        result[13] = currentState[1];

        // row 3 - shift 2 to the left
        result[2] = currentState[10];
        result[6] = currentState[14];
        result[10] = currentState[2];
        result[14] = currentState[6];

        // row 4 - shift 3 to the left
        result[3] = currentState[15];
        result[7] = currentState[3];
        result[11] = currentState[7];
        result[15] = currentState[11];

        // returns the resultant byte array
        return result;
    }

    /**
     * Multiplying by 3 in the AES field
     * 
     * @param b - byte that is being multiplied
     * 
     * @return returns the resultant byte after the operation
     */
    public static byte multiplyBy3(byte b) {
        // using the xtimes function to perform the operation
        return (byte) (xtimes(b) ^ b);
    }

    /**
     * Performs the mixColumns function
     * Multiplies a 4x4 matrix by a 4x1 vector
     * 
     * @param state - byte array representing the current state of the bytes
     * 
     * @return returns a byte array after the mixColumns function is completed
     */
    public static byte[] mixColumns(byte[] state) {
        // creating a new array to hold the resultant bytes after the operation
        byte[] result = new byte[16];

        // looping through each column
        for (int c = 0; c < 4; c++) {
            int i = c * 4;

            // finding the bytes in the current column
            byte s0 = state[i];
            byte s1 = state[i + 1];
            byte s2 = state[i + 2];
            byte s3 = state[i + 3];

            // performing the multiplication to each byte in the column
            result[i]     = (byte) (xtimes(s0) ^ multiplyBy3(s1) ^ s2 ^ s3);
            result[i + 1] = (byte) (s0 ^ xtimes(s1) ^ multiplyBy3(s2) ^ s3);
            result[i + 2] = (byte) (s0 ^ s1 ^ xtimes(s2) ^ multiplyBy3(s3));
            result[i + 3] = (byte) (multiplyBy3(s0) ^ s1 ^ s2 ^ xtimes(s3));
        }

        // returning the resultant array of bytes
        return result;
    }


    /* Helper Functions for File and Byte Array Generation */

    /**
     * Reading the file and putting it in a string
     * 
     * @param filePath - filename
     * 
     * @return returns a string of the file contents
     */
    public static String readFileToString(String filePath) throws IOException {
        Path path = Paths.get(filePath);

        // using another JAVA library to convert contents to a string
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    /**
     * Turning bytes into hex values
     * 
     * @param byteArray - array of bytes
     * 
     * @return returns a string of hex values
     */
    public static String bytesToHex(byte[] byteArray) {
        // initializing a new string
        StringBuilder hexString = new StringBuilder();

        // looping through each byte in the array
        for (byte b : byteArray) {
            // converting to hex values and adding them to the string
            hexString.append(String.format("%02X", b));
        }

        // returning the resultant string
        return hexString.toString().toLowerCase();
    }

    /**
     * Converts a string of hex values to a byte array
     * 
     * @param s - string of hex values
     * 
     * @return returns a byte array representing the hex values from the string
     */
    public static byte[] hexStringToByteArray(String s) {
        // length of the hex string
        int len = s.length();

        // creating a new byte array with the required length
        byte[] data = new byte[len / 2];
        
        // looping through the string
        for (int i = 0; i < len; i += 2) {
            // converting the hex values into bytes and inputting them into the byte array
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                            + Character.digit(s.charAt(i+1), 16));
        }

        // returning the byte array
        return data;
    }


    /* Key Expansion Functions */

    /**
     * Performs the core key expansion functions on four bytes
     * 
     * @param byte1 - the first byte
     * @param byte2 - the second byte
     * @param byte3 - the third byte
     * @param byte4 - the fourth byte
     * @param round - round number
     * 
     * @return return a byte array of the new four bytes
     */
    public static byte[] keyExpansionCore(byte byte1, byte byte2, byte byte3, byte byte4, int round) {
        // rotate bytes to the left
        byte[] rotatedBytes = rotateLeft(byte1, byte2, byte3, byte4);

        // substitute the bytes
        byte subByte1 = subBytes(rotatedBytes[0]);
        byte subByte2 = subBytes(rotatedBytes[1]);
        byte subByte3 = subBytes(rotatedBytes[2]);
        byte subByte4 = subBytes(rotatedBytes[3]);

        // add the round constant to the bytes
        byte[] finalKeyExpansion = addRoundConstant(subByte1, subByte2, subByte3, subByte4, round);

        // return the resultant array of bytes
        return finalKeyExpansion;
    }

    /**
     * Perform key expansion on a key of 128-bits
     * 
     * @param initialKey - initial key that was inputted by the user
     * 
     * @return returns a byte array of the expanded key
     */
    public static byte[] keyExpansion128(byte[] initialKey) {
        // copying the initial key to the beginning of the expanded key array
        byte[] expansionKey = Arrays.copyOf(initialKey, initialKey.length);

        // setting the round and the number of bytes that have already been generated
        int round = 1;
        int bytesGenerated = 16;

        // looping through the expansion key array
        while (expansionKey.length < 176) {
            for (int i = 0; i < 4 && bytesGenerated < 176; i++) {

                // array of the last four bytes of the expansion key
                byte[] temp1 = Arrays.copyOfRange(expansionKey, expansionKey.length - 4, expansionKey.length);

                if (i == 0) {
                    // calculating new bytes
                    temp1 = keyExpansionCore(temp1[0], temp1[1], temp1[2], temp1[3], round);
                }

                // getting the first four bytes of the last 16 bytes
                byte[] temp2 = Arrays.copyOfRange(expansionKey, expansionKey.length - 16, expansionKey.length - 12);

                // creating new array to hold the xor resultant bytes
                byte[] xor = new byte[4];

                // checking to make sure both arrays are the same length
                if (temp1.length == temp2.length) {
                    
                    // looping through the length of one array
                    for (int j = 0; j < temp1.length; j++) {

                        // xor each element from both arrays
                        xor[j] = (byte) (temp1[j] ^ temp2[j]);
                    }
                }
                else {
                    System.out.println("cannot XOR because of array length difference");
                }

                // appending the 4 newly generated bytes to the expansion key
                expansionKey = appendToExpansionKey(expansionKey, xor);

                // incrementing bytesGenerated to make sure the key does not go over a certain length
                bytesGenerated += 4;
            }

            // incrementing the round count
            round++;
        }

        // returning the byte array representing the expanded key
        return expansionKey;
    }

    /**
     * Perform key expansion on a key of 192-bits
     * 
     * @param initialKey - initial key that was inputted by the user
     * 
     * @return returns a byte array of the expanded key
     */
    public static byte[] keyExpansion192(byte[] initialKey) {
        // copying the initial key to the beginning of the expanded key array
        byte[] expansionKey = Arrays.copyOf(initialKey, initialKey.length);

        // setting the round and the number of bytes that have already been generated
        int round = 1;
        int bytesGenerated = 24;

        // looping through the expansion key array
        while (expansionKey.length < 216) {
            for (int i = 0; i < 6 && bytesGenerated < 216; i++) {

                // array of the last four bytes of the expansion key
                byte[] temp1 = Arrays.copyOfRange(expansionKey, expansionKey.length - 4, expansionKey.length);

                if (i == 0) {
                    // calculating new bytes
                    temp1 = keyExpansionCore(temp1[0], temp1[1], temp1[2], temp1[3], round);
                }

                // getting the first four bytes of the last 16 bytes
                byte[] temp2 = Arrays.copyOfRange(expansionKey, expansionKey.length - 24, expansionKey.length - 20);

                // creating new array to hold the xor resultant bytes
                byte[] xor = new byte[4];

                // checking to make sure both arrays are the same length
                if (temp1.length == temp2.length) {

                    // looping through the length of one array
                    for (int j = 0; j < temp1.length; j++) {

                        // xor each element from both arrays
                        xor[j] = (byte) (temp1[j] ^ temp2[j]);
                    }
                }
                else {
                    System.out.println("cannot XOR because of array length difference");
                }

                // appending the 4 newly generated bytes to the expansion key
                expansionKey = appendToExpansionKey(expansionKey, xor);

                // incrementing bytesGenerated to make sure the key does not go over a certain length
                bytesGenerated += 4;
            }

            // incrementing the round count
            round++;
        }

        // returning the byte array representing the expanded key
        return expansionKey;
    }

    /**
     * Perform key expansion on a key of 256-bits
     * 
     * @param initialKey - initial key that was inputted by the user
     * 
     * @return returns a byte array of the expanded key
     */
    public static byte[] keyExpansion256(byte[] initialKey) {
        // copying the initial key to the beginning of the expanded key array
        byte[] expansionKey = Arrays.copyOf(initialKey, initialKey.length);

        // setting the round and the number of bytes that have already been generated
        int round = 1;
        int bytesGenerated = 32;

        // looping through the expansion key array
        while (expansionKey.length < 256) {
            for (int i = 0; i < 8 && bytesGenerated < 256; i++) {
                
                // array of the last four bytes of the expansion key
                byte[] temp1 = Arrays.copyOfRange(expansionKey, expansionKey.length - 4, expansionKey.length);

                if (i == 0) {
                    // calculating new bytes
                    temp1 = keyExpansionCore(temp1[0], temp1[1], temp1[2], temp1[3], round);
                }

                if (i == 4) {
                    // substituting bytes when half way through
                    temp1 = subBytes(temp1);
                }

                // getting the first four bytes of the last 16 bytes
                byte[] temp2 = Arrays.copyOfRange(expansionKey, expansionKey.length - 32, expansionKey.length - 28);

                // creating new array to hold the xor resultant bytes
                byte[] xor = new byte[4];

                // checking to make sure both arrays are the same length
                if (temp1.length == temp2.length) {
                    
                    // looping through the length of one array
                    for (int j = 0; j < 4; j++) {

                        // xor each element from both arrays
                        xor[j] = (byte) (temp1[j] ^ temp2[j]);
                    }
                }
                else {
                    System.out.println("cannot XOR because of array length difference: " + temp1.length + ", " + temp2.length);
                }

                // appending the 4 newly generated bytes to the expansion key
                expansionKey = appendToExpansionKey(expansionKey, xor);

                // incrementing bytesGenerated to make sure the key does not go over a certain length
                bytesGenerated += 4;
            }

            // incrementing the round count
            round++;
        }

        // returning the byte array representing the expanded key
        return expansionKey;
    }


    /* Key Expansion Helper Functions */

    /**
     * Appending four bytes to the current expansion key
     * 
     * @param expansionKey - current state of the expansion key
     * @param appendBytes - bytes to append to the expansion key
     * 
     * @return returns a byte array with the new bytes added
     */
    public static byte[] appendToExpansionKey(byte[] expansionKey, byte[] appendBytes) {
        // checking if the number of bytes to add is 4
        if (appendBytes.length != 4) {
            System.out.println("appendBytes is not of the required length: " + appendBytes.length);
        }

        // creating a new array to add the bytes to 
        byte[] newExpansionKey = new byte[expansionKey.length + appendBytes.length];

        // copying the current expansion key to the new array
        System.arraycopy(expansionKey, 0, newExpansionKey, 0, expansionKey.length);

        // copying the four new bytes to the new array
        System.arraycopy(appendBytes, 0, newExpansionKey, expansionKey.length, appendBytes.length);

        // returning the new array with the added bytes
        return newExpansionKey;
    }

    /**
     * Adds a round constant to a byte array
     * 
     * @param byte1 - the first byte
     * @param byte2 - the second byte
     * @param byte3 - the third byte
     * @param byte4 - the fourth byte
     * @param round - the current round number
     * 
     * @return returns a byte array with the new first byte
     */
    public static byte[] addRoundConstant(byte byte1, byte byte2, byte byte3, byte byte4, int round) {
        // getting the round constant for the current round
        byte rcon = generateRcon(round);

        // creating a new array to hold the new bytes
        byte[] result = new byte[4];

        // xor the first byte and the round constant that was generated
        result[0] = (byte) (byte1 ^ rcon);

        // adding the other bytes to the new array
        result[1] = byte2;
        result[2] = byte3;
        result[3] = byte4;

        // returning the resultant array
        return result;
    }

    /**
     * Generates a new round constant depending on the round number
     * 
     * @param round - the current round number
     * 
     * @return returns a byte representing the generated round constant
     */
    public static byte generateRcon(int round) {
        // sets the first round constant
        byte current = 0x01;

        // loops through the number of rounds
        for (int i = 1; i < round; i++) {
            // calculates xtimes the current value
            current = xtimes(current);
        }

        // returns the resultant byte
        return current;
    }

    /**
     * Substitutes bytes based on the s-box
     * 
     * @param b - byte to be substituted
     * 
     * @return returns the substituted byte
     */
    public static byte subBytes(byte b) {
        // using the sbox to find the substitution
        return AESConstants.sbox[b & 0xFF];
    }

    /**
     * Substitutes an array of bytes based on the s-box
     * 
     * @param state - array of bytes to be substituted
     * 
     * @return returns an array where all the bytes were substituted
     */
    public static byte[] subBytes(byte[] state) {
        // creating a new array to hold the substituted bytes
        byte[] result = new byte[state.length];

        // looping through the array and substituting each byte
        for (int i = 0; i < state.length; i++) {
            // using the subBytes function to substitute each byte
            result[i] = subBytes(state[i]);
        }

        // returns the array with the substituted bytes
        return result;
    }

    /**
     * Rotates the bytes to the left
     * 
     * @param b1 - the first byte
     * @param b2 - the second byte
     * @param b3 - the third byte
     * @param b4 - the fourth byte
     * 
     * @return returns a byte array with the bytes rotated to the left
     */
    public static byte[] rotateLeft(byte b1, byte b2, byte b3, byte b4) {
        // creates a new array which includes the rotated to the left
        return new byte[] {b2, b3, b4, b1};
    }

    /**
     * Performs multiplication by x
     * 
     * @param b - byte to perform the operation on
     * 
     * @return returns the byte after the operation is completed
     */
    public static byte xtimes(byte b) {
        // returns the resultant byte after the operation
        return (byte) ((b << 1) ^ (((b & 0x80) != 0) ? 0x1b : 0x00));
    }

}