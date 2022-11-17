package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Arrays;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3AgentCommunicationPublicSpace {

    public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        /*
            FIXME: Defense #2

            The idea is to hide which bytes are actually being compared
            by MAC-ing the tags once more and then comparing those tags
         */
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create a ChaCha20 key that is used by Alice and the public-space
        // Create an AES key that is used by Bob and the public-space
        final Key keyAlicePublicSpace = KeyGenerator.getInstance("ChaCha20").generateKey();
        final SecretKey keyBobPublicSpace = KeyGenerator.getInstance("AES").generateKey();

        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Alice sends the data directly to Bob
                // The channel between Alice and Bob is not secured
                // Alice then computes the digest of the data and sends the digest to public-space
                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.
                send("bob", data);
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] hashed = digestAlgorithm.digest(data);
                final Cipher alice = Cipher.getInstance("ChaCha20-Poly1305");
                System.out.println("Alice data: " + Agent.hex(hashed));
                final byte[] nonce = new byte[12];
                new SecureRandom().nextBytes(nonce);
                alice.init(Cipher.ENCRYPT_MODE, keyAlicePublicSpace, new IvParameterSpec(nonce));
                final byte[] ct = alice.doFinal(hashed);

                send("public-space", ct);
                send("public-space", nonce);

            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice
                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob

                byte[] hash = receive("alice");
                byte[] nonce = receive("alice");
                final Cipher publicSpace = Cipher.getInstance("ChaCha20-Poly1305");
                publicSpace.init(Cipher.DECRYPT_MODE, keyAlicePublicSpace, new IvParameterSpec(nonce));
                byte[] digest = publicSpace.doFinal(hash);
                System.out.println("Public space digest: " + Agent.hex(digest));
                final Cipher encript = Cipher.getInstance("AES/GCM/NoPadding");
                encript.init(Cipher.ENCRYPT_MODE, keyBobPublicSpace);
                byte[] cipheredDigest = encript.doFinal(digest);
                byte[] ivr = encript.getIV();

                send("bob", cipheredDigest);
                send("bob", ivr);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the data from Alice and compute the digest over it using SHA-256
                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space
                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"

                byte[] data = receive("alice");
                byte[] dataDigest = receive("public-space");
                byte[] ivr = receive("public-space");

                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                byte[] dataHashed = digestAlgorithm.digest(data);
                System.out.println("Bob data hashed: " + Agent.hex(dataHashed));

                final Cipher decr = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, ivr);
                decr.init(Cipher.DECRYPT_MODE, keyBobPublicSpace, specs);

                try {
                    final byte[] dt = decr.doFinal(dataDigest);
                    if (verify3(dataHashed, dt, key)) {
                        System.out.print("Data valid");
                    }
                    else {
                        System.out.println("Data invalid");
                    }
                } catch(AEADBadTagException e) {
                    System.out.println("The digest was modified!");
                }
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
}
