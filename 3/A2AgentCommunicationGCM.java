package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationGCM {
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
                for (int i = 0; i < 10; i++) {
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice. Message: " + i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);

                    final byte[] iv = alice.getIV();

                    send("bob", iv);
                    send("bob", ct);

                    final byte[] cipher = receive("bob");
                    final byte[] ivrec = receive("bob");
                    final Cipher decr = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, ivrec);
                    decr.init(Cipher.DECRYPT_MODE, key,specs);
                    try {
                        final byte[] dt = decr.doFinal(cipher);
                        System.out.println("[MESSAGE] " + new String(dt));
                    }
                    catch(AEADBadTagException e){
                        System.out.println("THE Message was modified!!");
                    }


                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    final byte[] iv = receive("alice");
                    final byte[] ct = receive("alice");
                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);

                    final byte[] pt2 = bob.doFinal(ct);

                    System.out.println("Received message: " + new String(pt2));

                    final String reply = "Hi Alice."+"Reply:"+i;
                    final Cipher encr = Cipher.getInstance("AES/GCM/NoPadding");
                    encr.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encr.doFinal(reply.getBytes());
                    final byte[] ivr = encr.getIV();
                    System.out.println("[CT] " + Agent.hex(cipherText));
                    send("alice", cipherText);
                    send("alice", ivr);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
