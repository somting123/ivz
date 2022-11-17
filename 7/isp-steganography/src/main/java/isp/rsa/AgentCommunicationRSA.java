package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final String algorithm = "RSA/ECB/OAEPPadding";

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                - Create an RSA cipher and encrypt a message using Bob's PK;
                - Send the CT to Bob;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                final byte[] pt = "Hello Bob, Alice here!".getBytes(StandardCharsets.UTF_8);

                final Cipher rsaEnc = Cipher.getInstance(algorithm);
                rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                final byte[] ct = rsaEnc.doFinal(pt);

                send("bob", ct);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                - Take the incoming message from the queue;
                - Create an RSA cipher and decrypt incoming CT using Bob's SK;
                - Print the message;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                final byte[] ct = receive("alice");

                final Cipher rsaDec = Cipher.getInstance(algorithm);
                rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] pt = rsaDec.doFinal(ct);

                print("Got: \"" + new String(pt, StandardCharsets.UTF_8) + "\"");
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
