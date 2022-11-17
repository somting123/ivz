package isp.secrecy;

import java.lang.reflect.Array;
import java.security.Key;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import fri.isp.Agent;

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

    public static byte[] generateKey() {
        
        byte[] key1 = new byte[6];
        byte[] key2 = new byte[2];

        Random random = new Random();
        random.nextBytes(key2);

        byte[] key = new byte[key1.length + key2.length];
        System.arraycopy(key1, 0, key, 0, key1.length);
        System.arraycopy(key2, 0, key, key1.length, key2.length);

        // System.out.println("[key]  : " + Agent.hex(key));
        return key;
    }

    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        byte[] byteKey = generateKey();
        // byte[] byteKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte)0x45};
        final Key key = new SecretKeySpec(byteKey, 0, byteKey.length, "DES");

        System.out.println("Key: " + Agent.hex(key.getEncoded()));

        final byte[] pt = message.getBytes();
        System.out.println("[PT] " + Agent.hex(pt));

        final Cipher encrypt = Cipher.getInstance("DES");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = encrypt.doFinal(pt);

        System.out.println("[CT] " + Agent.hex(cipherText));

        byte[] bfKey = bruteForceKey(cipherText, message);

        if (bfKey != null) {
            System.out.println("[Success] Brute forced key:" + Agent.hex(bfKey));
        } else {
            System.out.println("[Failure] Key not found");
        }

    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        
        final byte[] pt = message.getBytes();
        final Cipher decrypt = Cipher.getInstance("DES");
        byte[] tmpByteKey = new byte[8];
        
        for (int i = 0; i < 256; i++) {
            tmpByteKey[5] = (byte) i;
            // System.out.println("[Test key] " + Agent.hex(tmpByteKey));
            for (int j = 0; j < 256; j++) {
                tmpByteKey[6] = (byte) j;
                // System.out.println("[Test key] " + Agent.hex(tmpByteKey));
                for (int k = 0; k < 256; k++) {            
                    tmpByteKey[7] = (byte) k;
                    // System.out.println("[Test key] " + Agent.hex(tmpByteKey));
                    try {
                        Key tmpKey = new SecretKeySpec(tmpByteKey, "DES");
                        // System.out.println("[Test key] " + Agent.hex(tmpByteKey));

                        decrypt.init(Cipher.DECRYPT_MODE, tmpKey);
                        byte[] ptTmp = decrypt.doFinal(ct);

                        if (Arrays.equals(pt, ptTmp)) {
                            // System.out.println("[*****Key found*****] " + Agent.hex(tmpByteKey));
                            // tmpByteKey[7] += (byte)1;
                            return tmpByteKey;
                        }
                    }
                    catch (Exception e){}
                }
            }
        }

        return null;
    }
}
