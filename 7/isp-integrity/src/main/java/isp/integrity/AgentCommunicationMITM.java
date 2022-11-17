package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * As the person in the middle (MITM), intercept a message from Alice,
 * modify the message as instructed, and create a MAC tag that will verify successfully.
 * <p>
 * Useful resources:
 * - SHA-1 RFC https://tools.ietf.org/html/rfc3174 (section o padding in particular)
 * - Wikipedia entry: https://en.wikipedia.org/wiki/Length_extension_attack
 * <p>
 * You can assume to know the length of the plaintext and the length of the secret that is used
 * for MAC-ing.
 * <p>
 * To manually set the internal state of the SHA-1 algorithm, use the {@link ModifiedSHA1} class.
 */
public class AgentCommunicationMITM {

    public static void main(String[] args) throws Exception {
        // Alice and the bank have a shared secret, and its length is known to the attacker.
        final byte[] sharedSecret = new byte[16];

        // For debugging purposes, I recommend using a static secret (like all zeros).
        // Your solution, however, must work with an arbitrary secret.
        // So for debugging, comment out the following two lines.
        final SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(sharedSecret);

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "Wire 10 EUR to MITM.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                final MessageDigest d = MessageDigest.getInstance("SHA-1");
                d.update(sharedSecret);
                d.update(pt);
                final byte[] tag = d.digest();

                print("data  = %s", message);
                print("pt    = %s", hex(pt));
                print("tag   = %s", hex(tag));

                send("bank", pt);
                send("bank", tag);
            }
        });

        env.add(new Agent("mitm") {
            @Override
            public void task() throws Exception {
                final byte[] pt = receive("alice");
                final byte[] tag = receive("alice");
                final String message = new String(pt, StandardCharsets.UTF_8);
                print("data    = %s", message);
                print("pt      = %s", hex(pt));
                print("tag     = %s", hex(tag));

                // TODO: Extend the message and produce a valid tag without knowing the shared secret.
                // (However, you do know the length of the shared secret [and the length of the message].)

                // Data to be added
                final byte[] addition = "And then, in a separate transaction, wire 1,000,000 EUR more."
                        .getBytes(StandardCharsets.UTF_8);

                // Calculate the length of the padded message in bytes
                int paddedPTlen = pt.length + 72 - 16; // subtract first 16 bytes because of shared secret
                paddedPTlen -= paddedPTlen % 64 + 16;

                // Copy and pad the message
                byte[] paddedPT = new byte[paddedPTlen];
                System.arraycopy(pt, 0, paddedPT, 0, pt.length);
                paddedPT[pt.length] = (byte) 0x80; // initial bit
                long msgLen = (16 + pt.length) * 8; // ShS + msg
                byte[] msgLenAsBytes = ByteBuffer.allocate(8).putLong(msgLen).array();
                System.arraycopy(msgLenAsBytes, 0, paddedPT, paddedPTlen - 8, 8);

                // Prepare the hashing algorithm
                ModifiedSHA1 hasher = new ModifiedSHA1();
                hasher.setState(tag, (paddedPTlen + 16) / 64);
                hasher.update(addition);

                // Form final message and tag
                byte[] finalTag = hasher.digest();
                byte[] finalPT = new byte[paddedPTlen + addition.length];
                System.arraycopy(paddedPT, 0, finalPT, 0, paddedPTlen);
                System.arraycopy(addition, 0, finalPT, paddedPTlen, addition.length);

                send("bank", finalPT);
                send("bank", finalTag);
            }
        });

        env.add(new Agent("bank") {
            @Override
            public void task() throws Exception {
                final byte[] pt = receive("alice");
                final byte[] tag = receive("alice");

                // recompute the tag
                final MessageDigest d = MessageDigest.getInstance("SHA-1");
                d.update(sharedSecret);
                d.update(pt);
                final byte[] tagComputed = d.digest();

                print("data = %s", new String(pt, StandardCharsets.UTF_8));
                print("pt   = %s", hex(pt));

                if (Arrays.equals(tag, tagComputed))
                    print("MAC verification succeeds: %s == %s", hex(tag), hex(tagComputed));
                else
                    print("MAC verification fails: %s != %s", hex(tag), hex(tagComputed));
            }
        });

        env.mitm("alice", "bank", "mitm");
        env.start();
    }
}
