package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Midterm {
    public static void main(String[] args) throws Exception {
        Environment env = new Environment();
        final String algorithm = "RSA/ECB/OAEPPadding";
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair aliceKP = kpg.generateKeyPair();
        final KeyPair serverKP = kpg.generateKeyPair();
        final String password = "password";
        env.add(new Agent("alice") {
            public void task() throws Exception {
                final SecretKey sharedKey = KeyGenerator.getInstance("AES").generateKey();
                final Cipher rsaEnc = Cipher.getInstance(algorithm);
                rsaEnc.init(Cipher.ENCRYPT_MODE, serverKP.getPublic());
                final byte[] seckeyenc = rsaEnc.doFinal(Base64.getEncoder().encodeToString(sharedKey.getEncoded()).getBytes(StandardCharsets.UTF_8));
                send("server",seckeyenc);
                String secret = "SECRET";
                final byte[] hash=hash(1000,secret.getBytes(StandardCharsets.UTF_8));

                final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                alice.init(Cipher.ENCRYPT_MODE, sharedKey);
                final byte[] ct = alice.doFinal(hash);
                final byte[] iv=alice.getIV();
                send("server",ct);
                send("server",iv);
                System.out.println(Agent.hex(hash));
                send("lock",hash(999,secret.getBytes(StandardCharsets.UTF_8)));
            }
        });
        env.add(new Agent("server") {
            public void task() throws Exception {
                final byte[] seckeyenc=receive("alice");
                //System.out.println(seckeyenc);
                final Cipher rsaDec = Cipher.getInstance(algorithm);
                rsaDec.init(Cipher.DECRYPT_MODE, serverKP.getPrivate());
                final byte[] decryptedText = rsaDec.doFinal(seckeyenc);
                //System.out.println(decryptedText);
                byte[] decodedKey = Base64.getDecoder().decode(decryptedText);
                SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

                final byte[] ct=receive("alice");
                final byte[] iv=receive("alice");
                final Cipher servcip = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                servcip.init(Cipher.DECRYPT_MODE, originalKey, specs);
                final byte[] token = servcip.doFinal(ct);

                System.out.println(Agent.hex(token));

                final byte[] salt = "89fjh3409fdj390fk".getBytes(StandardCharsets.UTF_8);

                final byte[] mac=mac(token,password,salt);

                send("lock",token);
                send("lock",salt);
                send("lock",mac);
                System.out.println(Agent.hex(token));


            }
        });
        env.add(new Agent("lock") {
            public void task() throws Exception {
                final byte[] token=receive("server");
                final byte[] salt=receive("server");
                final byte[] mac=receive("server");
                System.out.println(Agent.hex(token));
                if(verify(token,mac,password,salt)){

                    final byte[] local_token=token;
                    final byte[] rec_tok=receive("alice");

                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed = digestAlgorithm.digest(rec_tok);

                    final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

                    if(verify_tokens(local_token,hashed,key)){
                        System.out.println("SUCCESS");
                    }
                    else{
                        System.out.println("FAILURE");
                    }
                }
            }
        });

        env.connect("alice", "server");
        env.connect("alice", "lock");
        env.connect("server", "lock");
        env.start();
    }

    /**
     * Verifies the MAC tag.
     *
     * @param payload  the message
     * @param tag      the MAC tag
     * @param password the password form which MAC key is derived
     * @param salt     the salt used to strengthen the password
     * @return true iff. the verification succeeds, false otherwise
     */
    public static boolean verify(byte[] payload, byte[] tag, String password, byte[] salt) throws Exception {
        final byte[] mac=mac(payload,password,salt);
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        final Mac MAC = Mac.getInstance("HmacSHA256");
        MAC.init(key);

        final byte[] tagtag1 = MAC.doFinal(mac);
        final byte[] tagtag2 = MAC.doFinal(tag);

        return Arrays.equals(tagtag1, tagtag2);
    }


    /**
     * Computes the MAC tag over the message.
     *
     * @param payload  the message
     * @param password the password form which MAC key is derived
     * @param salt     the salt used to strengthen the password
     * @return the computed tag
     */
    public static byte[] mac(byte[] payload, String password, byte[] salt) throws Exception {
        final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt, 1000, 128);
        final SecretKey generatedKey = pbkdf.generateSecret(specs);

        final Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
        final byte[] mac=hmac.doFinal(payload);
        return mac;
    }

    /**
     * Hashes the given payload multiple times.
     *
     * @param times   the number of times the value is hashed
     * @param payload the initial value to be hashed
     * @return the final hash value
     */
    public static byte[] hash(int times, byte[] payload) throws Exception {
        final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");

        byte[] hashed = digestAlgorithm.digest(payload);
        for(int i=0;i<times-1;i++){ //times-1 ker zgoraj ze enkrat hashamo
            hashed=digestAlgorithm.digest(hashed);
        }
        return hashed;
    }

    public static boolean verify_tokens(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {

        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }
}
