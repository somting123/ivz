package isp.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

import fri.isp.Agent;
import fri.isp.Environment;

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
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();;
        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();;

        final String algorithm = "RSA/ECB/OAEPPadding";

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for(int i = 0; i < 6; i++) {
                    if (i == 0) {
                        final String message = "Wassup, Bob.";
                        final byte[] pt = message.getBytes();

                        final Cipher rsaEnc = Cipher.getInstance(algorithm);
                        rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                        final byte[] ct = rsaEnc.doFinal(pt);

                        send("bob", ct);
                    } else {
                        final byte[] rct = receive("bob");

                        final Cipher rsaDec = Cipher.getInstance(algorithm);
                        rsaDec.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                        final byte[] dt = rsaDec.doFinal(rct);
    
                        print("Received: " + new String(dt));
    
                        if (i < 6){
                            final String message = "No, wassup to you, Bob.";
                            final byte[] pt = message.getBytes();
        
                            final Cipher rsaEnc = Cipher.getInstance(algorithm);
                            rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                            final byte[] ct = rsaEnc.doFinal(pt);
        
                            send("bob", ct);
                        }
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                for(int i = 0; i < 5; i++) {
                    final byte[] rct = receive("alice");

                    final Cipher rsaDec = Cipher.getInstance(algorithm);
                    rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] dt = rsaDec.doFinal(rct);

                    print("Received: " + new String(dt));


                    final String message = "Wassup to you, Alice.";
                    final byte[] pt = message.getBytes();

                    final Cipher rsaEnc = Cipher.getInstance(algorithm);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());
                    final byte[] ct = rsaEnc.doFinal(pt);

                    send("alice", ct);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
