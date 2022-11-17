package isp.signatures;

import fri.isp.Agent;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;

public class KeyDerivation {
    public static void main(String[] args) throws Exception {
        // password from which the key will be derived
        final String password = "my password";

        // supposed to be random
        final byte[] salt = "89fjh3409fdj390fk".getBytes(StandardCharsets.UTF_8);

        final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        // provide the password, salt, number of iterations and the number of required bits
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt, 1000000, 128);
        final SecretKey key = pbkdf.generateSecret(specs);

        System.out.printf("key = %s%n", Agent.hex(key.getEncoded()));
        System.out.printf("len(key) = %d bytes", key.getEncoded().length);
    }
}
