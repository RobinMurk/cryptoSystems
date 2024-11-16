package appcrypto;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

// took 5 hours (please specify here how much time your solution required)
//main issues were with jdk and setting the project

public class TestApplet extends Applet {
	
	private KeyPair keypair;
	private RSAPublicKey pub;
	private Cipher rsa;
	
	public static void install(byte[] ba, short offset, byte len) {
		(new TestApplet()).register();
	}

	private TestApplet() {
		rsa = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
	}
	
	public void process(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		short len;

		switch (buf[ISO7816.OFFSET_INS]) {
		case (0x02): //generate RSA keys
			if(keypair == null){
				keypair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
				keypair.genKeyPair();
				pub = (RSAPublicKey) keypair.getPublic();
				rsa.init(keypair.getPrivate(), Cipher.MODE_DECRYPT);
				return;
			}
			return;
		case (0x04): //request the exponent of public key
			if (pub == null){
				ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
			}

			len = pub.getExponent(buf, (short)0);
			apdu.setOutgoingAndSend((short)0, len);
			return;
		case (0x06): //request the modulus of public key
			len = pub.getModulus(buf, (short)0);
			apdu.setOutgoingAndSend((short)0, len);
			return;
		case (0x08): //decrypt data
			if (buf[ISO7816.OFFSET_LC] == (byte)0) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}

			len = (short)(buf[ISO7816.OFFSET_LC] & (short)0xff);
			byte p1 = buf[ISO7816.OFFSET_P1];
			byte p2 = buf[ISO7816.OFFSET_P2];

			byte[]data = JCSystem.makeTransientByteArray(
				(short)256, 
				JCSystem.CLEAR_ON_DESELECT
				);
			data[0] = p1;
			data[1] = p2;

			apdu.setIncomingAndReceive();

			Util.arrayCopyNonAtomic(
				buf, 
				ISO7816.OFFSET_CDATA, 
				data, 
				(short)2, 
				len
				);
			len = rsa.doFinal(
				data,
				(short)0,
				(short)256,
				buf,
				(short)0);
			apdu.setOutgoingAndSend((short)0, len);
			return;
		}
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);		
	}
}
