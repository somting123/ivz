package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.net.FileNameMap;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;


public class A1Midterm {

    public static void main(String[] args) throws Exception {

        // region Create two public-secret key pairs
        final KeyPairGenerator kpgA = KeyPairGenerator.getInstance("RSA");
        kpgA.initialize(2048);
        final KeyPair kpA = kpgA.generateKeyPair();

        final KeyPairGenerator kpgB = KeyPairGenerator.getInstance("RSA");
        kpgB.initialize(2048);
        final KeyPair kpB = kpgB.generateKeyPair();
        // endregion

        // region Shared secret
        final KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
        dhGen.initialize(2048);

        final KeyPair kpAlice = dhGen.generateKeyPair();
        final KeyPair kpBob = dhGen.generateKeyPair();

        final Environment env = new Environment();



        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // Shared secred key establishment
                    //Send PK to BOB
                    send("bob", kpAlice.getPublic().getEncoded());

                    //Get PK from BOB
                    // 25%
                    final X509EncodedKeySpec keySpecAlice = new X509EncodedKeySpec(receive("bob"));
                    final DHPublicKey bobPublic = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpecAlice);

                    final KeyAgreement dhAliceAgreement = KeyAgreement.getInstance("DH");
                    dhAliceAgreement.init(kpAlice.getPrivate());
                    dhAliceAgreement.doPhase(bobPublic,true);

                    final char[] password = "wkgjfklegjeklgjeklgjdklfgjlroptti490ti9w0iwkdWEF$$WGG$#T3".toCharArray();
                    final byte [] secretAsSalt = dhAliceAgreement.generateSecret();

                    //Super secret
                    final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                    final KeySpec  keySpec = new PBEKeySpec(password,secretAsSalt,1000,128);
                    final SecretKey superDuperSecretKeyForAlice = pbkdf.generateSecret(
                            new PBEKeySpec(password,secretAsSalt,1000,128)
                    );


                 final Cipher aliceEnc = Cipher.getInstance("AES/GCM/NoPadding");
                 aliceEnc.init(Cipher.DECRYPT_MODE,superDuperSecretKeyForAlice);
                 byte [] iv = aliceEnc.getIV();


                 //Alice creates the message (digest).

                String message = "Ragnarok is comming";
                final byte[] hashed = hash(1000,message.getBytes(StandardCharsets.UTF_8));
                send("bob",hashed);



                final PublicKey bobKey = kpB.getPublic();

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                //Send PK to BOB
                send("alice", kpBob.getPublic().getEncoded());

                //Get PK from BOB
                // 25%
                final X509EncodedKeySpec keySpecAlice = new X509EncodedKeySpec(receive("alice"));
                final DHPublicKey bobPublic = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpecAlice);

                final KeyAgreement dhAliceAgreement = KeyAgreement.getInstance("DH");
                dhAliceAgreement.init(kpAlice.getPrivate());
                dhAliceAgreement.doPhase(bobPublic,true);

                final char[] password = "aaaaaaaaaaaaaroptti490ti9w0iwkdWEF$$WGG$#T3".toCharArray();
                final byte [] secretAsSalt = dhAliceAgreement.generateSecret();

                //Super secret
                final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                final KeySpec  keySpec = new PBEKeySpec(password,secretAsSalt,1000,128);
                final SecretKey superDuperSecretKeyForBob = pbkdf.generateSecret(
                        new PBEKeySpec(password,secretAsSalt,1000,128)
                );
                final byte [] EncrypteedHashFromAlice = receive("alice");
                final byte [] hashFromAlice = receive("alice");
                final byte[] timeStampBytes = longToByteArray(System.currentTimeMillis());
                byte [] payload = payloadFromArray(hashFromAlice,timeStampBytes);

               // Sign.
                final Signature signer = Signature.getInstance("RSA");
                signer.initSign(kpBob.getPrivate());
                signer.update(payload);
                final byte[] signature = signer.sign();

                Cipher bobEnc = Cipher.getInstance("AES/GCM/NoPadding");
                bobEnc.init(Cipher.ENCRYPT_MODE,superDuperSecretKeyForBob);
                byte [] iv = bobEnc.getIV();
                byte [] ctPayload = bobEnc.doFinal(payload);
                byte [] ctSign = bobEnc.doFinal(signature);

                send("server", iv);
                send("server", ctPayload);
                send("server", ctSign);

               final PublicKey aliceKey = kpA.getPublic();


            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                //Send PK to BOB

              }
        });

        env.connect("alice", "bob");
        env.connect("bob","server");
        env.connect("server","alice");

        env.start();

        /**
         * Verifies the MAC tag.
         *
         * @param payload  the message
         * @param tag      the MAC tag
         * @param password the password form which MAC key is derived
         * @param salt     the salt used to strengthen the password
         * @return true iff. the verification succeeds, false otherwise
         */
    }
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
    public static byte[] longToByteArray(final long i) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeLong(i);
        dos.flush();
        return bos.toByteArray();
    }

    public static byte [] payloadFromArray(byte[] firstArray, byte[] secondArray){
        byte [] payload  = new byte[firstArray.length + secondArray.length];

        for(int i = 0 ;i < payload.length; i++){
            if(i < firstArray.length){
                Array.setByte(payload,i,firstArray[i]);
            } else{
                Array.setByte(payload,i,secondArray[i-firstArray.length]);
            }
        }

        return  payload;

    }
    }

