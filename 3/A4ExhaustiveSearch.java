package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.util.Arrays;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);
        final byte[] kb ={0, 0, 0, 0, 0, 14, 23, 22};
        final Key key = new SecretKeySpec(kb,"DES");
        final byte[] pt = message.getBytes();

        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = encrypt.doFinal(pt);
        System.out.println("[CT] " + Agent.hex(cipherText));
        byte[] kljuc = bruteForceKey(cipherText,message);
        System.out.println(Arrays.toString(kljuc));
        System.out.println(Arrays.toString(kb));
    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        for(int i = 0; i < 128; i++){
            for(int j = 0; j < 128; j++){
                for(int k = 0; k < 128; k++){
                    final byte[] testni_kljuc ={0,0,0,0,0,(byte)i,(byte)j,(byte)k};
                    final Key key = new SecretKeySpec(testni_kljuc,"DES");
                    final Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding");
                    des.init(Cipher.DECRYPT_MODE, key);
                    try {
                        final byte[] dt = des.doFinal(ct);
                        if (new String(dt).equals(message)) {
                            System.out.println(new String(dt));
                            return testni_kljuc;
                        }
                    }
                    catch(BadPaddingException ignored){

                    }
                }
            }
        }

        return null;
    }
}