package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
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
 * using HMAC implemented with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {

    public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        /*
            FIXME: Defense #2

            The idea is to hide which bytes are actually being compared
            by MAC-ing the tags once more and then comparing those tags
         */
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String text = "I hope you get this message intact. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                final Mac alice = Mac.getInstance("HmacSHA256");
                alice.init(key);
                final byte[] tag1 = alice.doFinal(text.getBytes(StandardCharsets.UTF_8));

                send("bob", pt);
                send("bob", tag1);

                for (int i = 0; i < 10; i++) {
                    final byte[] ptRec = receive("bob");
                    final byte[] tagRec = receive("bob");
                    final byte[] tag2 = alice.doFinal(pt);

                    System.out.println(new String(ptRec));
                    if (!verify3(tagRec, tag2, key)) {
                        final String sendText = "Sending message number " + i + " to Alice.";
                        final byte[] odg = sendText.getBytes(StandardCharsets.UTF_8);
                        final byte[] tag_i = alice.doFinal(odg);
                        send("bob", odg);
                        send("bob", tag_i);
                    }
                    else {
                        final String sendText = "Sending message number " + i + " to Alice.";
                        final byte[] odg = sendText.getBytes(StandardCharsets.UTF_8);
                        final byte[] tag_i = alice.doFinal(odg);
                        send("bob", odg);
                        send("bob", tag_i);
                    }
                    System.out.println();
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final Mac bob = Mac.getInstance("HmacSHA256");
                bob.init(key);

                for (int i = 0; i < 10; i++) {
                    final byte[] pt = receive("alice");
                    final byte[] tag = receive("alice");
                    final byte[] tag2 = bob.doFinal();

                    System.out.println(new String(pt));
                    if (verify3(tag, tag2, key)) {
                        final String sendText = "Sending message number " + i + " to Bob.";
                        final byte[] odg = sendText.getBytes(StandardCharsets.UTF_8);
                        final byte[] tag_i = bob.doFinal(odg);
                        send("alice", odg);
                        send("alice", tag_i);
                    }
                    else {
                        final String sendText = "Sending message number " + i + " to Bob.";
                        final byte[] odg = sendText.getBytes(StandardCharsets.UTF_8);
                        final byte[] tag_i = bob.doFinal(odg);
                        send("alice", odg);
                        send("alice", tag_i);
                    }
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
