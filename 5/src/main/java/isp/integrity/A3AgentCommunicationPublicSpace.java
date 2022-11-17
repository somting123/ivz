package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

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
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create a ChaCha20 key that is used by Alice and the public-space
        // Create an AES key that is used by Bob and the public-space
        final Key keyCha = KeyGenerator.getInstance("ChaCha20").generateKey();
        final Key keyAES = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Alice sends the data directly to Bob
                send("bob", data);
                // The channel between Alice and Bob is not secured
                // Alice then computes the digest of the data and sends the digest to public-space
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] hashData = digestAlgorithm.digest(data);

                // final String hashAsHex = Agent.hex(hashData);
                // System.out.println(hashAsHex);

                byte[] nonce = new byte[12];
                new SecureRandom().nextBytes(nonce);

                final Cipher encrypt = Cipher.getInstance("ChaCha20-Poly1305");
                IvParameterSpec iv = new IvParameterSpec(nonce);
                encrypt.init(Cipher.ENCRYPT_MODE, keyCha, iv);
                byte[] cipherHashData = encrypt.doFinal(hashData);

                send("public-space", cipherHashData);
                send("public-space", nonce);
                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.

            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice
                byte[] cipherHashData = receive("alice");
                byte[] nonce = receive("alice");

                Cipher decrypt = Cipher.getInstance("ChaCha20-Poly1305");
                IvParameterSpec iv = new IvParameterSpec(nonce);
                decrypt.init(Cipher.DECRYPT_MODE, keyCha, iv);
                // final byte[] publicHashData = decrypt.doFinal(cipherHashData); 

                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob
                final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                encrypt.init(Cipher.ENCRYPT_MODE, keyAES); 
                final byte[] cipherHashDataAES = encrypt.doFinal(decrypt.doFinal(cipherHashData));
                final byte[] iv2 = encrypt.getIV();

                send("bob", cipherHashDataAES);
                send("bob", iv2);

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the data from Alice and compute the digest over it using SHA-256
                byte[] data = receive("alice");

                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] hashData = digestAlgorithm.digest(data);

                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space
                final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");

                final byte[] cipherHashDataAES = receive("public-space");
                final byte[] iv = receive("public-space");

                final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                bob.init(Cipher.DECRYPT_MODE, keyAES, specs);
                final byte[] hashDataAES = bob.doFinal(cipherHashDataAES);

                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
                Boolean dataValid = verify(hashData, hashDataAES);
                if (dataValid) {
                    print("Data valid");
                } else {
                    print("Data invalid");
                }
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
    
    public static boolean verify(byte[] tag1, byte[] tag2)
            throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance("HmacSHA256");
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }
}
