package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */

        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        final Mac a = Mac.getInstance("HmacSHA256");
        a.init(key);

        final Environment env = new Environment();

        //Podatki
        final String aliceSaysToBob [] = new String[]{
                "Leave me alone  6!",
                "Leave me alone  7!",
                "Leave me alone  8!",
                "Leave me alone  9!",
                "Leave me alone  10!"
        };

        final String bobSaysToAlice []  = new String[]{
                "Leave me alone  1!",
                "Leave me alone  2!",
                "Leave me alone  3!",
                "Leave me alone  4!",
                "Leave me alone  5!"
        };

            env.add(new Agent("alice") {
                @Override
                public void task() throws Exception {

                    // A to B za A
                    byte[] plainTextBytes = "I love you Bob. Kisses, Alice.".getBytes(StandardCharsets.UTF_8);
                    byte[] tagFromAlice = a.doFinal(plainTextBytes);

                    send("bob", plainTextBytes);
                    send("bob", tagFromAlice);

                    // B to A

                    byte[] bobFromMsg = receive("alice");
                    byte[] tagFromTheSameMessage = receive("alice");

                    byte[] newTagFromBobMsg = a.doFinal(bobFromMsg);

                    if (verify3()) {
                        "Yippie Kay yaaay motherfucker."
                    } else {
                        "Que?"
                    }
                    // Za B obrneš prejemnike/pošiljatelje.

                    //DODAJ VERIFY 2
                }
            });
            env.connect("alice", "bob");
            env.start();
        }

    public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {

        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }
}
