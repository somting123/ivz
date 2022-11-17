package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * A communication channel is implemented with thread-safe blocking queue.
 * <p/>
 * Both agents are implemented by extending the Agents class,
 * creating anonymous class and overriding #execute().
 * <p/>
 * Both agents are started at the end of the main method definition below.
 */
public class AgentCommunication {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() {
                for(int i = 0; i < 3; i++) {
                    final byte[] payload = ("Hi, Bob, this is Alice. " + i).getBytes();
                    send("bob", payload);
                    final byte[] received = receive("bob");
                    print("Got '%s', converted to string: '%s'", hex(received), new String(received));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() {
                send("alice", "Hey Alice, Bob here.".getBytes());
                print("Got '%s'", new String(receive("alice")));

                send("alice", "Hey Alice, Bob here 2.".getBytes());
                print("Got '%s'", new String(receive("alice")));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
