package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/*
 * Message Authenticity and Integrity are provided using Hash algorithm and Shared Secret Key.
 * http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Mac
 */
public class AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * STEP 1: Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * STEP 3.
                 * Alice
                 * - creates a message;
                 * - computes the tag using the HMAC-SHA-256 algorithm and the shared key;
                 * - sends a message that is comprised of:
                 *   - message,
                 *   - tag.
                 */
                final String text = "I hope you get this message intact. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                final Mac alice = Mac.getInstance("HmacSHA256");
                alice.init(key);
                final byte[] tag = alice.doFinal(pt);

                send("bob", pt);
                send("bob", tag);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob:
                 * - receives the message that is comprised of:
                 *   - message, and
                 *   - tag;
                 * - uses shared secret session key to verify the message
                 */
                final byte[] pt = receive("alice");
                final byte[] rec_tag = receive("alice");

                print("Message: " + new String(pt, StandardCharsets.UTF_8));

                final Mac alice = Mac.getInstance("HmacSHA256");
                alice.init(key);
                final byte[] calc_tag = alice.doFinal(pt);

                if (HMACExample.verify3(rec_tag, calc_tag, key))
                    print("Tags match!");
                else
                    print("Tags do NOT match!");
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
