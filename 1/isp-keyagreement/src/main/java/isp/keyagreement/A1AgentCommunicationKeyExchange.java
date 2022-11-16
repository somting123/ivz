package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/*
 * Implement a key exchange between Alice and Bob using public-key encryption.
 * Once the shared secret is established, send an encrypted message from Alice to Bob using
 * AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("EC");
                keyGenerator.initialize(256);

                final KeyPair keyPair = keyGenerator.generateKeyPair();
                send("bob", keyPair.getPublic().getEncoded());


                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("bob"));
                final ECPublicKey bobPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(bobPK, true);

                final byte[] sharedSecret = dh.generateSecret();
                final SecretKeySpec Key = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, Key);


                String message = "Hey Bob look at this cool new message metod!";
                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();

                send("bob", iv);
                send("bob", ct);

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final ECPublicKey alicePK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
                final ECParameterSpec dhParamSpec = alicePK.getParams();

                final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("EC");
                keyGenerator.initialize(dhParamSpec);
                final KeyPair keyPair = keyGenerator.generateKeyPair();
                send("alice", keyPair.getPublic().getEncoded());

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(alicePK, true);
                final byte[] sharedSecret = dh.generateSecret();
                final SecretKeySpec Key = new SecretKeySpec(sharedSecret, 0, 16, "AES");



                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, Key, new GCMParameterSpec(128, iv));
                final byte[] pt = aes.doFinal(ct);

                print("Got: %s", new String(pt, StandardCharsets.UTF_8));

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}