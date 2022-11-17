package isp.signatures;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import fri.isp.Agent;
import fri.isp.Environment;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        // Create key pairs
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        KeyPair pairAlice = keyGen.generateKeyPair();
        KeyPair pairBob = keyGen.generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message signarure pair, verify the signature
                // repeat 10 times

                for(int i = 0; i < 6; i++) {
                    if (i == 0) {
                        Signature ecdsa = Signature.getInstance("SHA256withECDSA");

                        ecdsa.initSign(pairAlice.getPrivate());

                        String message = "Hello, Bob.";
                        byte[] pt = message.getBytes("UTF-8");
                        ecdsa.update(pt);
                        byte[] signature = ecdsa.sign();
                        // print("Signature: " + hex(signature));

                        send("bob", pt);
                        send("bob", signature);
                    } else {

                        byte[] pt2 = receive("bob");
                        byte[] tag = receive("bob");

                        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
                        ecdsa.initVerify(pairBob.getPublic());
                        ecdsa.update(pt2);
                        print("Signat. "+ ecdsa.verify(tag));

                        if (i < 5) {
                            ecdsa.initSign(pairAlice.getPrivate());

                            String message = "Hello, Bob.";
                            byte[] pt = message.getBytes("UTF-8");
                            ecdsa.update(pt);
                            byte[] signature = ecdsa.sign();
                            // print("Signature: " + hex(signature));

                            send("bob", pt);
                            send("bob", signature);
                        }
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                for(int i = 0; i < 5; i++) {
                    byte[] pt = receive("alice");
                    byte[] tag = receive("alice");

                    Signature ecdsa = Signature.getInstance("SHA256withECDSA");
                    ecdsa.initVerify(pairAlice.getPublic());
                    ecdsa.update(pt);
                    print("Signat. "+ ecdsa.verify(tag));

                    ecdsa.initSign(pairBob.getPrivate());

                    String message = "Hello, Alice.";
                    byte[] pt2 = message.getBytes("UTF-8");
                    ecdsa.update(pt2);
                    byte[] realSig = ecdsa.sign();
                    // System.out.println("Signature: " + new BigInteger(1, realSig).toString(16));

                    send("alice", pt2);
                    send("alice", realSig);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}