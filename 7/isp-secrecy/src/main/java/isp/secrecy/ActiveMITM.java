package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class ActiveMITM {
    public static void main(String[] args) throws Exception {
        // David and SMTP server both know the same shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("david") {
            @Override
            public void task() throws Exception {
                final String message = "from: ta.david@fri.uni-lj.si\n" +
                        "to: prof.denis@fri.uni-lj.si\n\n" +
                        "Hi! Find attached <some secret stuff>!";

                final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();
                print("sending: '%s' (%s)", message, hex(ct));
                send("server", ct);
                send("server", iv);
            }
        });

        env.add(new Agent("student") {
            @Override
            public void task() throws Exception {
                final byte[] bytes = receive("david");
                final byte[] iv = receive("david");
                print(" IN: %s", hex(bytes));

                // As the person-in-the-middle, modify the ciphertext
                // so that the SMTP server will send the email to you
                // (Needless to say, you are not allowed to use the key
                // that is being used by david and server.)

                bytes[33] ^= 'p' ^ 's';
                bytes[34] ^= 'r' ^ 'a';
                bytes[35] ^= 'o' ^ 'm';
                bytes[36] ^= 'f' ^ 'p';
                bytes[37] ^= '.' ^ 'l';
                bytes[38] ^= 'd' ^ 'e';
                bytes[39] ^= 'e' ^ '@';
                bytes[40] ^= 'n' ^ 's';
                bytes[41] ^= 'i' ^ 't';
                bytes[42] ^= 's' ^ 'u';
                bytes[43] ^= '@' ^ 'd';
                bytes[44] ^= 'f' ^ 'e';
                bytes[45] ^= 'r' ^ 'n';
                bytes[46] ^= 'i' ^ 't';

                print("OUT: %s", hex(bytes));
                send("server", bytes);
                send("server", iv);
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                final byte[] ct = receive("david");
                final byte[] iv = receive("david");
                final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                final byte[] pt = aes.doFinal(ct);
                final String message = new String(pt, StandardCharsets.UTF_8);

                print("got: '%s' (%s)", message, hex(ct));
            }
        });

        env.mitm("david", "server", "student");
        env.start();
    }
}
