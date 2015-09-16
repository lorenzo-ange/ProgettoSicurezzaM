import diffiehellman.client.ClientThread;
import diffiehellman.server.ServerThread;


public class Test {

	public static void main(String[] args) {

		(new Thread(new ServerThread())).start();
		(new Thread(new ClientThread())).start();

	}
}
