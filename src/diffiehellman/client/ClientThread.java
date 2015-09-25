package diffiehellman.client;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

public class ClientThread implements Runnable {

	private static int serverPort = 8412;
	private static String serverAddr = "localhost";

	public void run() {

		// Inizializzazione della Socket
		Socket server = null;
		try {
			server = new Socket(serverAddr, serverPort);
		} catch (IOException e) {
			System.out.println("Unable to reach server");
			e.printStackTrace();
			return;
		}

		// Crea stream di in/out
		ObjectOutputStream outSocket = null;
		ObjectInputStream inSocket = null;
		try {
			outSocket = new ObjectOutputStream(server.getOutputStream());
			inSocket = new ObjectInputStream(server.getInputStream());
		} catch (IOException e) {
			System.out.println("Unable to get socket streams");
			e.printStackTrace();
			return;
		}

		// Adesso la connessione è correttamente stabilita
		try {
			SecretKey key = AESDHKeyAgreement(outSocket, inSocket);

			String times = String.valueOf(4);
			sendAESCryptedString(times, key, outSocket);

			String cleartext;
			do {
				cleartext = receiveAESCryptedString(key, inSocket);
				System.out.println("Client: decrypted text: "+cleartext);
			} while(!cleartext.equals("stop"));

		} catch (Exception e) {
			System.out.println("Client: ERROR");
			e.printStackTrace();
		}
	}

	public SecretKey AESDHKeyAgreement(ObjectOutputStream outSocket, ObjectInputStream inSocket) throws Exception {
		/* Il Client genera i parametri g e p, operazione costosa
		 * p: numero primo
		 * g: generatore del gruppo moltiplicativo degli interi modulo p
		 */
		System.out.println("Creating Diffie-Hellman parameters (takes VERY long) ...");
		AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
		paramGen.init(1024);
		AlgorithmParameters params = paramGen.generateParameters();
		DHParameterSpec dhSkipParamSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);

		/* Il Client crea la sua coppia di chiavi DH utilizzando i parametri generati sopra
		 * SK = a: numero casuale
		 * PK = (g,p,A)
		 * A: (g^a) mod p
		 */
		System.out.println("Client: Generate DH keypair ...");
		KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
		clientKpairGen.initialize(dhSkipParamSpec);
		KeyPair clientKpair = clientKpairGen.generateKeyPair();

		// Il Client codifica la sua chiave pubblica e la invia al Server
		byte[] clientPubKeyEnc = clientKpair.getPublic().getEncoded();
		outSocket.writeObject(clientPubKeyEnc);

		/*
		 * Il Client riceve la chiave pubblica DH del Server in forma codificata.
		 * Istanzia un oggetto PublicKey dai dati che ha ricevuto
		 */
		byte[] serverPubKeyEnc = (byte[]) inSocket.readObject();
		KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
		PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

		/* Il Client crea ed inizializza un oggetto KeyAgreement di DH che,
		 * grazie alla SK del Client e alla PK del Server,
		 * può calcolare la chiave concordata K
		 * K = (serverPK^a) mod p = (B^a) mod p = (g^ab) mod p
		 */
		System.out.println("Client: Initialization ...");
		KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
		clientKeyAgree.init(clientKpair.getPrivate());
		System.out.println("Client: calculating agreed KEY ...");
		clientKeyAgree.doPhase(serverPubKey, true);

		/*
		 * A questo punto sia il Client che il Server hanno completato il protocollo di DH.
		 * Hanno ottenuto entrambi la chiave concordata K
		 */
		return clientKeyAgree.generateSecret("AES");
	}

	private void sendAESCryptedString(String cleartext, SecretKey key, ObjectOutputStream outSocket) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encodedParams = cipher.getParameters().getEncoded();
		outSocket.writeObject(encodedParams);
		byte[] ciphertext = cipher.doFinal(cleartext.getBytes());
		outSocket.writeObject(ciphertext);
	}

	private String receiveAESCryptedString(SecretKey key, ObjectInputStream inSocket) throws Exception {
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
