package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;

/**
 * EXERCISE:
 * - Study the example
 * - Play with different ciphers
 * <p>
 * - Homework: Oscar intercepts the message and would like to decrypt the ciphertext. Help Oscar to
 * decrypt the cipher text using brute force key search (exhaustive key search) if Oscar knows
 * that Alice has send the following message "I would like to keep this text confidential Bob. Kind regards, Alice."
 * (Known-plaintext attack) (Use DES and manually set a poor key; class {@link javax.crypto.spec.SecretKeySpec})
 * <p>
 * https://docs.oracle.com/javase/10/security/java-cryptography-architecture-jca-reference-guide.htm
 */
public class SymmetricCipherExample {
    // STREAM CIPHERS
    // RC4

    // BLOCK CIPHERS
    // DES with padding: "DES/ECB/PKCS5Padding"
    // Tripple DES with padding: "DESede/ECB/PKCS5Padding"
    // AES in ECB with padding: "AES/ECB/PKCS5Padding"
    // AES in CBC with padding, "AES/CBC/PKCS5Padding"
    // AES in CTR without padding: "AES/CTR/NoPadding"

    // private static byte[] weakDESkey = {0x75, 0x40, (byte)0xB5, (byte)0xA7, (byte)0xE9, (byte)0xD0, (byte)0xDC, 0x75};
    private static byte[] weakDESkey = {0x00, 0x00, 0x00, 0x00, 0x00, (byte)0xD0, (byte)0xDC, 0x75};

    private static byte[] bruteForceKey(byte[] pt, byte[] ct, String ciph) throws Exception{
        final Cipher encryption = Cipher.getInstance(ciph);
        for (int i3 = 0; i3 < 256; i3++)
            for (int i2 = 0; i2 < 256; i2++)
                for (int i1 = 0; i1 < 256; i1++)
                    for (int i0 = 0; i0 < 256; i0++) {
                        byte[] trialKey = {0, 0, 0, 0, (byte)i3, (byte)i2, (byte)i1, (byte)i0};
                        final Key key = new SecretKeySpec(trialKey, 0, 8, ciph);
                        encryption.init(Cipher.ENCRYPT_MODE, key);
                        byte[] cipherText = encryption.doFinal(pt);
                        if (Arrays.equals(cipherText, ct))
                            return trialKey;
                    }

        return null;

    }

    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        String ciphName = "DES";

        // STEP 1: Alice and Bob agree upon a cipher and a shared secret key
        // final Key key = KeyGenerator.getInstance(ciphName).generateKey();
        final Key key = new SecretKeySpec(weakDESkey, 0, weakDESkey.length, ciphName);
        System.out.println("Key: " + Agent.hex(key.getEncoded()));

        final byte[] clearText = message.getBytes();
        System.out.println("[PT] " + Agent.hex(clearText));

        //  STEP 2: Create a cipher, encrypt the PT and, optionally, extract cipher parameters (such as IV)
        final Cipher encryption = Cipher.getInstance(ciphName);
        encryption.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = encryption.doFinal(clearText);

        // STEP 3: Print out cipher text (in HEX) [this is what an attacker would see]
        System.out.println("[CT] " + Agent.hex(cipherText));

        // MITM: brute-force the secret key
        byte[] bfKey = bruteForceKey(clearText, cipherText, ciphName);
        if (bfKey != null)
            System.out.println("[O] Found key! " + Agent.hex(bfKey));
        else
            System.out.println("[O] Key not found.");
        /*
         * STEP 4.
         * The receiver creates a Cipher object, defines the algorithm, the secret key and
         * possibly additional parameters (such as IV), and then decrypts the cipher text
         */
        final Cipher decryption = Cipher.getInstance(ciphName);
        decryption.init(Cipher.DECRYPT_MODE, key);
        final byte[] decryptedText = decryption.doFinal(cipherText);
        System.out.println("[PT] " + Agent.hex(decryptedText));

        // Todo: What happens if the key is incorrect? (Try with RC4 or AES in CTR mode)

        // STEP 5: Create a string from a byte array
        System.out.println("[MESSAGE] " + new String(decryptedText));
    }
}
