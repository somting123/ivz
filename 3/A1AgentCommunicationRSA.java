package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Assuming Alice and Bob know each other's public key, secure the channel using a
 * RSA. Then exchange ten messages between Alice and Bob.
 *
 * (The remaining assignment(s) can be found in the isp.steganography.ImageSteganography
 * class.)
 */
public class A1AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        // Create two public-secret key pairs
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair bobKP = kpg.generateKeyPair();
        final KeyPair aliceKP = kpg.generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    String message = "Hey, Bob " + i;
                    byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                    final byte[] ct = rsaEnc.doFinal(pt);

                    send("bob", ct);

                    // Bob receives
                    byte[] ct2 = receive("bob");
                    final Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    rsaDec.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(ct2);

                    final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
                    System.out.println(message2);

                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    byte[] ct = receive("alice");
                    final Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(ct);

                    final String message = new String(decryptedText, StandardCharsets.UTF_8);
                    System.out.println(message);

                    String reply = "Hello to you too, Alice " + i;
                    byte[] pt = reply.getBytes(StandardCharsets.UTF_8);
                    final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    rsaEnc.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());
                    final byte[] ct2 = rsaEnc.doFinal(pt);

                    send("alice", ct2);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
