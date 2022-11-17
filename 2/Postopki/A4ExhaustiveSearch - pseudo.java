package isp.secrecy;

import fri.isp.Agent;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.lang.reflect.Array;
import java.util.Random;


/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of th last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {
    private static byte[] byteKey;

    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        //Set the upper 40 bits to be zeroes and the lower 24 bits to be random values.
         byte [] byteKey = generateByteKey(8);

        // Testing


        System.out.println(Agent.hex(byteKey));
        final Cipher desEcb  = Cipher.getInstance("DES/ECB/PKCS5Padding");
        final SecretKeySpec key = new SecretKeySpec(byteKey,"DES");
        desEcb.init(Cipher.ENCRYPT_MODE, key);

        final byte [] bruteForcedKey = bruteForceKey(desEcb.doFinal(message.getBytes()),message);

        if(bruteForcedKey == null){
            System.out.println("Your code goofed up");
        } else{
            System.out.println("Key: " + Agent.hex(bruteForcedKey));
        }
    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        // TODO
        byte [] cleanArray = setZeroes(8);
        int maxIterations = 16777216;
        int currentNumberOfIterations = 0;

        for (byte a =-128; a <= 127; a++) {
            for (byte b =-128; b <= 127; b++)  {
                for (byte c =-128; c <= 127; c = (byte) ((byte) c+1)) { //
                    currentNumberOfIterations++;

                    Array.setByte(cleanArray,5,(byte)a);
                    Array.setByte(cleanArray,6,(byte)b);
                    Array.setByte(cleanArray,7,(byte)c);

                    try {
                        // Return byteKey.
                        final Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
                        SecretKeySpec key = new SecretKeySpec(cleanArray, "DES");

                        decrypt.init(Cipher.DECRYPT_MODE, key);
                        final byte[] dt2 = decrypt.doFinal(ct);

                        if (new String(dt2).equals(message)) {
                            return dt2;
                        }
                    }
                    catch (Exception e){

                    }

                    // If key not found return null;
                    if(currentNumberOfIterations == maxIterations){
                        System.out.println("No key found. Check your code.");
                        return null;
                    }

                    if (c == 127) {
                        Array.setByte(cleanArray,7, (byte) 0x00);
                        break;
                    }
                }

                if(b == 127) {
                    Array.setByte(cleanArray,7, (byte) 0x00);
                    break;
                }
            }
            System.out.println("Broken out of b loop.");
            if(a == 127) {
                Array.setByte(cleanArray,6, (byte) 0x00);
                break;
            }
        }
        return null;
    }

    public static byte[] generateByteKey(int arraySize){

        Random random = new Random();
        byte [] byteKey = new byte[arraySize];
        random.nextBytes(byteKey);

        return setZeroes(byteKey,5);
    }

    public static byte[] setZeroes(byte [] randomByteArray, int upperIndex){

        for(int i = 0; i < upperIndex; i++){
            randomByteArray[i] = 0x00;
        }

        return randomByteArray;
    }
    public static byte[] setZeroes(int arraySize){
       return setZeroes(new byte[arraySize], arraySize);
    }



}
