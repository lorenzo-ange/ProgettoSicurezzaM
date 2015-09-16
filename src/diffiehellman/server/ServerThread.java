package diffiehellman.server;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class ServerThread implements Runnable {

	private int serverPort = 8412;

	public ServerThread() {
	}

	public void run() {
		// Socket in ascolto su localhost
		ServerSocket server = null;
		try {
			server = new ServerSocket(serverPort);
			System.out.println("Server listening on "+serverPort);
		} catch (IOException e) {
			System.out.println("Error while starting server");
			e.printStackTrace();
			return;
		}

		// Loop infinito di accettazione richieste di connessione
		while(true)
		{
			Socket socket = null;
			try {
				socket = server.accept();
				// Nuova connessione
				System.out.println("New Connection on port : " + socket.getLocalPort());
			} catch (IOException e) {
				System.out.println("Error while enstablishing connection");
				e.printStackTrace();
				continue;
			}

			// Crea stream di in/out
			ObjectOutputStream outSocket;
			ObjectInputStream inSocket;
			try {
				outSocket = new ObjectOutputStream(socket.getOutputStream());
				inSocket = new ObjectInputStream(socket.getInputStream());

			} catch (IOException e) {
				System.out.println("Unable to get socket streams");
				e.printStackTrace();
				continue;
			}

			// Adesso la connessione è correttamente stabilita
			try {
				SecretKey key = AESDHKeyAgreement(outSocket, inSocket);

				String cleartext = receiveAESCryptedString(key, outSocket, inSocket);
				System.out.println("Server: decrypted text: "+cleartext);

				int times = Integer.parseInt(cleartext);
				for(int i = 0; i<times; i++) {
					String SysLoadAvg = String.valueOf(ManagementFactory.getOperatingSystemMXBean().getSystemLoadAverage());
					sendAESCryptedString(SysLoadAvg, key, outSocket, inSocket);
					Thread.sleep(2000);
				}
				sendAESCryptedString("stop", key, outSocket, inSocket);

			} catch (Exception e) {
				System.out.println("Server: ERROR");
				e.printStackTrace();
				continue;
			}
		}
	}

	public SecretKey AESDHKeyAgreement(ObjectOutputStream outSocket, ObjectInputStream inSocket) throws Exception {

		/*
		 * Il Server riceve la chiave pubblica DH del Client in forma codificata.
		 * Istanzia un oggetto PublicKey dai dati che ha ricevuto
		 */
		byte[] clientPubKeyEnc = (byte[]) inSocket.readObject();
		KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);
		PublicKey clientPubKey = serverKeyFac.generatePublic(x509KeySpec);

		/*
		 * Il Server preleva i parametri di DH associati alla chiave pubblica del Client.
		 * PK = (g,p,A)
		 * p: numero primo
		 * g: generatore del gruppo moltiplicativo degli interi modulo p
		 * A: (g^a) mod p
		 * Gli serviranno per generare la sua coppia di chiavi DH
		 */
		DHParameterSpec dhParamSpec = ((DHPublicKey) clientPubKey).getParams();

		/* Il Server genera la sua coppia di chiavi DH
		 * SK = b: numero casuale
		 * PK = B: (g^b) mod p
		 */
		System.out.println("Server: Generate DH keypair ...");
		KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
		serverKpairGen.initialize(dhParamSpec);
		KeyPair serverKpair = serverKpairGen.generateKeyPair();

		// Il Server codifica la sua chiave pubblica e la invia al Client
		byte[] serverPubKeyEnc = serverKpair.getPublic().getEncoded();
		outSocket.writeObject(serverPubKeyEnc);

		/* Il Server crea ed inizializza un oggetto KeyAgreement di DH che,
		 * grazie alla SK del Server e alla PK del Client,
		 * può calcolare la chiave concordata K
		 * K = (clientPK^b) mod p = (A^b) mod p =(g^ab) mod p
		 */
		System.out.println("Server: Initialization ...");
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
		serverKeyAgree.init(serverKpair.getPrivate());
		System.out.println("Server: calculating agreed KEY ...");
		serverKeyAgree.doPhase(clientPubKey, true);

		/*
		 * A questo punto sia il Client che il Server hanno completato il protocollo di DH.
		 * Hanno ottenuto entrambi la chiave concordata K
		 */
		return serverKeyAgree.generateSecret("AES");
	}

	private void sendAESCryptedString(String cleartext, SecretKey key, ObjectOutputStream outSocket, ObjectInputStream inSocket) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);

		byte[] encodedParams = cipher.getParameters().getEncoded();
		outSocket.writeObject(encodedParams);

		byte[] ciphertext = cipher.doFinal(cleartext.getBytes());
		outSocket.writeObject(ciphertext);
	}

	private String receiveAESCryptedString(SecretKey key, ObjectOutputStream outSocket, ObjectInputStream inSocket) throws Exception {
		byte[] encodedParams = (byte[]) inSocket.readObject();
		AlgorithmParameters params = AlgorithmParameters.getInstance("AES");
		params.init(encodedParams);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, params);
		byte[] ciphertext = (byte[]) inSocket.readObject();
		byte[] recovered = cipher.doFinal(ciphertext);
		return new String(recovered);
	}
}
