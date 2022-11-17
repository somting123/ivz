package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

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

                for(int i = 0; i < 11; i++) {
                    if (i == 0) {
                        final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                        final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                        final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                        alice.init(Cipher.ENCRYPT_MODE, key); 
                        final byte[] ct = alice.doFinal(pt);

                        final byte[] iv = alice.getIV();
                        // System.out.printf("IV:  %s%n", Agent.hex(iv));

                        send("bob", ct);
                        send("bob", iv);
                    } else {
                        final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");

                        final byte[] ct = receive("bob");
                        final byte[] iv = receive("bob");

                        final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                        alice.init(Cipher.DECRYPT_MODE, key, specs);
                        final byte[] pt2 = alice.doFinal(ct);

                        // System.out.printf("PT:  %s%n", Agent.hex(pt2));
                        print("MR: %s%n", new String(pt2, StandardCharsets.UTF_8));


                        final String text = "And the advesary? Kisses, Alice.";
                        final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                        // final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                        alice.init(Cipher.ENCRYPT_MODE, key); 
                        final byte[] ct2 = alice.doFinal(pt);

                        final byte[] iv2 = alice.getIV();
                        System.out.printf("IV:  %s%n", Agent.hex(iv));

                        send("bob", ct2);
                        send("bob", iv2);
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for(int i = 0; i < 10; i++) {
                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");

                    final byte[] ct = receive("alice");
                    final byte[] iv = receive("alice");

                    final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(ct);

                    // System.out.printf("PT:  %s%n", Agent.hex(pt2));
                    print("MR: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final String text = "Forget about it... We got GCM homie.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    // final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    bob.init(Cipher.ENCRYPT_MODE, key); 
                    final byte[] ct2 = bob.doFinal(pt);

                    final byte[] iv2 = bob.getIV();
                    System.out.printf("IV:  %s%n", Agent.hex(iv));

                    send("alice", ct2);
                    send("alice", iv2);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
