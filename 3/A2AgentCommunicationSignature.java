package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        final String signingAlgorithm ="SHA256withECDSA";
        final String keyAlgorithm = "EC";

        // Create key pairs
        final KeyPair bobKeyPair = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();
        final KeyPair aliceKeyPair = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message signarure pair, verify the signature
                // repeat 10 times
                for (int i = 0; i < 10; i++) {
                    final String message = "Hey Bob, this is Alice " + i;
                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(aliceKeyPair.getPrivate());
                    signer.update(message.getBytes(StandardCharsets.UTF_8));
                    final byte[] signature = signer.sign();

                    System.out.println("[BOB]: sending message: " + message);
                    send("bob", message.getBytes());
                    send("bob", signature);

                    final byte[] messsageFromBob = receive("bob");
                    final byte[] bobSign = receive("bob");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(bobKeyPair.getPublic());
                    verifier.update(messsageFromBob);

                    if (verifier.verify(bobSign))
                        System.out.println("[Bob]: Successfully received message: " + new String(messsageFromBob));
                    else
                        System.err.println("Invalid signature");
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    final byte[] messageReceived = receive("alice");
                    final byte[] signatureReceived = receive("alice");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(aliceKeyPair.getPublic());
                    verifier.update(messageReceived);

                    if (verifier.verify(signatureReceived))
                        System.out.println("[ALICE]: Successfully received message: " + new String(messageReceived));
                    else
                        System.err.println("Invalid signature");

                    final String messageBob = "Hey Alice, how are you? " + i;
                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(bobKeyPair.getPrivate());
                    signer.update(messageBob.getBytes(StandardCharsets.UTF_8));
                    final byte[] signatureBob = signer.sign();

                    System.out.println("[ALICE]: sending message: " + messageBob);
                    send("alice", messageBob.getBytes());
                    send("alice", signatureBob);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}