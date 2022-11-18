package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.net.FileNameMap;
import java.nio.charset.StandardCharsets;
import java.security.Key;
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
        final KeyPairGenerator kpgA = KeyPairGenerator.getInstance("RSA");
        final KeyPair kpA = kpgA.generateKeyPair();

        final KeyPairGenerator kpgB = KeyPairGenerator.getInstance("RSA");
        final KeyPair kpB = kpgB.generateKeyPair();

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
                final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
                final Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");

                for(int j = 0; j< 2; j++)
                {
                    for (byte i = 0; i < 5; i++) {
                        if (i % 2 == 1) {
                                rsaEnc.init(Cipher.ENCRYPT_MODE, kpB.getPublic());
                                send("bob", rsaEnc.doFinal(aliceSaysToBob[i].getBytes(StandardCharsets.UTF_8)));
                        } else {
                            rsaDec.init(Cipher.DECRYPT_MODE,kpA.getPrivate());
                            byte [] ct = receive("bob");
                            byte [] pt = rsaDec.doFinal(ct);
                            System.out.println("Bob says: "+
                                    new String(
                                            pt,
                                            StandardCharsets.UTF_8
                                    ));
                        }
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
                final Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");
                for (int j = 0; j<2; j++){
                    for (int i = 0; i < 5; i++) {
                        if (i % 2 == 0) {
                            rsaEnc.init(Cipher.ENCRYPT_MODE, kpA.getPublic());
                            send("alice", rsaEnc.doFinal(bobSaysToAlice[i].getBytes(StandardCharsets.UTF_8)));
                        } else {
                            rsaDec.init(Cipher.DECRYPT_MODE,kpB.getPrivate());
                            byte [] ct = receive("alice");
                            byte [] pt = rsaDec.doFinal(ct);
                            System.out.println("Alice says: "+
                                    new String(
                                            pt,
                                            StandardCharsets.UTF_8
                                    ));
                        }

                    }
                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
    }
