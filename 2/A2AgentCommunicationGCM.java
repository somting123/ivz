package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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
        final SecretKey sharedKey = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

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
                final Cipher a  = Cipher.getInstance("AES/GCM/NoPadding");
                final Cipher b  = Cipher.getInstance("AES/GCM/NoPadding");

                for(int j = 0; j< 2; j++) {
                    for (byte i = 0; i < 5; i++) {
                        if (i % 2 == 0) {
                            
                            
                            final byte[] pt = aliceSaysToBob[i].getBytes(StandardCharsets.UTF_8);
                            a.init(Cipher.ENCRYPT_MODE, sharedKey);
                            final byte [] ct = a.doFinal(pt);
                            send("bob", ct);
                            send("bob",a.getIV());
                            
                            
                        } else {
                            byte[] bobCt = receive("bob");
                            byte[] bobIv = receive("bob");
                            b.init(Cipher.DECRYPT_MODE,sharedKey,new GCMParameterSpec(128, bobIv));
                            byte[] bobMsg = b.doFinal(bobCt);
                            System.out.println("Bob wanna say: " + new String(bobMsg));
                        }
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                final Cipher a  = Cipher.getInstance("AES/GCM/NoPadding");
                final Cipher b  = Cipher.getInstance("AES/GCM/NoPadding");

                for(int j = 0; j< 2; j++) {
                    for (byte i = 0; i < 5; i++) {
                        if (i % 2 == 1) {
                            final byte[] pt = bobSaysToAlice[i].getBytes(StandardCharsets.UTF_8);
                            b.init(Cipher.ENCRYPT_MODE, sharedKey);
                            final byte [] ct = b.doFinal(pt);
                            send("alice", ct);
                            send("alice",b.getIV());
                        } else {
                            byte[] aliceCt = receive("alice");
                            byte[] aliceIv = receive("alice");
                            a.init(Cipher.DECRYPT_MODE,sharedKey,new GCMParameterSpec(128, aliceIv));
                            byte[] aliceMsg = a.doFinal(aliceCt);
                            System.out.println("Alice wanna say: " + new String(aliceMsg));
                        }

                    }
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
