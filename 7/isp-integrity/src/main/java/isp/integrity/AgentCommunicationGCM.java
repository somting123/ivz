package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * Alice:
                 * - creates an AES/GCM cipher,
                 * - initializes it for encryption and with given key.
                 * - encrypts the messages,
                 * - sends the ciphertext and the IV to Bob.
                 */
                final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                alice.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = alice.doFinal(pt);
                final byte[] iv = alice.getIV();
                print("CT: " + Agent.hex(ct));
                print("IV: " + Agent.hex(iv));

                send("bob", ct);
                send("bob", iv);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob:
                 * - receives the ciphertext and the IV
                 * - creates a AES/GCM cipher
                 * - initializes the cipher with decryption mode, the key and the IV
                 * - decrypts the message and prints it.
                 */
                final byte[] ct = receive("alice");
                final byte[] iv = receive("alice");

                final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                bob.init(Cipher.DECRYPT_MODE, key, specs);
                final byte[] pt = bob.doFinal(ct);

                print("PT: " + new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
