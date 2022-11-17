package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.lang.String;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
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

        // Signature
        final String signingAlgorithm =
        //  "SHA256withRSA";
        //  "SHA256withDSA";
        "SHA256withECDSA";

        final String keyAlgorithm ="EC";

        final KeyPair keyAlice  = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();
        final PublicKey keyAlicePublic = keyAlice.getPublic();

        final KeyPair keyBob  = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();
        final PublicKey keyBobPublic = keyBob.getPublic();
        final Signature signer = Signature.getInstance(signingAlgorithm);

        //Integrity Key
        final String password = "dfsfdslkfjsdlkfjskld";
        final byte [] salt = "kfjkfjsdkfjdoifjsfjskj4i0r49FGFG".getBytes(StandardCharsets.UTF_8);

        final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt,10000, 128);

        final SecretKey generatedKey = pbkdf.generateSecret(specs);
        final Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message signarure pair, verify the signature
                // repeat 10 times

                for(int j = 0; j< 2; j++)
                {
                    for (byte i = 0; i < 5; i++) {
                        if (i % 2 == 0) {

                            String message = aliceSaysToBob[i];
                            byte[] msgBytes = message.getBytes();


                            signer.initSign(keyAlice.getPrivate());
                            signer.update(message.getBytes(StandardCharsets.UTF_8));
                            byte [] signature = signer.sign();

                            byte [] payload = new byte[msgBytes.length+signature.length];

                            // Set payload (message and signature) to get integrity.
                            for(int k=0; k < payload.length; k++){

                                if(i < msgBytes.length){
                                    Array.setByte(payload,i,msgBytes[i]);
                                }
                                else{
                                    Array.setByte(payload,i,payload[i-msgBytes.length]);
                                }
                            }

                            byte[] aliceTag = hmac.doFinal(payload);

                            send("bob", payload);
                            send("bob", msgBytes);
                            send("bob", signature);
                            send("bob", aliceTag);
                        } else {
                            byte [] pld = receive("bob");
                            byte [] bMsg = receive("bob");
                            byte [] bSig = receive("bob");
                            byte[] bobTag1 = receive("bob");

                            final Signature verifier = Signature.getInstance(signingAlgorithm);
                            verifier.initVerify(keyBobPublic);
                            verifier.update(bMsg);

                            byte[] tag1 = hmac.doFinal(pld);

                            if (verify2(tag1, bobTag1) && verifier.verify(bSig)) {
                                System.out.println(new String(bMsg));
                            } else {

                                System.out.println("https://www.youtube.com/watch?v=2P5qbcRAXVk");
                            }
                        }
                        //   Thread.sleep(1000);
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                for (int j = 0; j<2; j++){
                    for (int i = 0; i < 5; i++) {
                        if (i % 2 == 1) {
                            byte [] message = bobSaysToAlice[i].getBytes();
                            signer.initSign(keyBob.getPrivate());
                            signer.update(message);

                            byte [] signature = signer.sign();

                            byte [] payload = new byte[message.length+signature.length];

                            // Set payload (message and signature) to get integrity.
                            for(int k=0; k< payload.length; k++){

                                if(i < message.length){
                                    Array.setByte(payload,i,message[i]);
                                }
                                else{
                                    Array.setByte(payload,i,payload[i-message.length]);
                                }
                            }

                            byte[] aliceTag = hmac.doFinal(payload);

                              send("alice", payload);
                            //  send("bob", message.length.ToString());
                            //To simplify the task
                            send("alice", message);
                            send("alice", signature);
                            send("alice", aliceTag);
                        } else {
                            byte [] payload = receive("alice");

                            byte [] AMsg = receive("alice");
                            byte [] ASig = receive("alice");
                            byte[] aliceTag1 = receive("alice");

                            final Signature verifier = Signature.getInstance(signingAlgorithm);
                            verifier.initVerify(keyAlicePublic);
                            verifier.update(AMsg);

                            byte[] tag1 = hmac.doFinal(payload);

                            if (verify2(tag1, aliceTag1) && verifier.verify(ASig)) {
                                System.out.println(new String(AMsg));
                            } else {

                                System.out.println("https://www.youtube.com/watch?v=2P5qbcRAXVk");
                            }
                        }
                        //Thread.sleep(1000);
                    }
                }
            }
        });

        /*

        public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {

            FIXME: Defense #2
            The idea is to hide which bytes are actually being compared
            by MAC-ing the tags once more and then comparing those tags

            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);

            final byte[] tagtag1 = mac.doFinal(tag1);
            final byte[] tagtag2 = mac.doFinal(tag2);

            return Arrays.equals(tagtag1, tagtag2);
        }*/



        env.connect("alice", "bob");
        env.start();
    }

    static boolean verify2(byte[] tag1, byte[] tag2){
        if (tag1 == tag2)
            return true;
        if (tag1 == null || tag2 == null)
            return false;

        int length = tag1.length;
        if (tag2.length != length)
            return false;

        // This loop never terminates prematurely
        byte result = 0;
        for (int i = 0; i < length; i++) {
            result |= tag1[i] ^ tag2[i];
        }
        return result == 0;
    }

    static byte [] mergeByteArray(byte [] firstArray, byte[] secondArray)
    {
        byte [] mergedArray = new byte[firstArray.length + secondArray.length];

        for(int i = 0; i < mergedArray.length; i++){
            if(i<firstArray.length){
                Array.setByte(mergedArray, i, firstArray[i]);
            }
            else{
                Array.setByte(mergedArray, i, secondArray[i - firstArray.length]);
            }
        }
        return mergedArray;

    }
}