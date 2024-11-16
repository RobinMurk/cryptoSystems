package appcrypto;

import java.applet.Applet;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

// took x.y hours (please specify here how much time your solution required)


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
		
		switch (buf[ISO7816.OFFSET_INS]) {
		case (0x02): //generate RSA keys
			if (buf[ISO7816.OFFSET_LC] != (byte)0) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			if(keypair == null){
				keypair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
				keypair.genKeyPair();
				pub = (RSAPublicKey) keypair.getPublic();
				rsa.init(keypair.getPrivate(), Cipher.MODE_DECRYPT);
				return;
			}
			return;
		case (0x04): //request the exponent of public key
			if (buf[ISO7816.OFFSET_LC] != (byte)0) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			if (pub == null){
				ISOException.throwIt("No keypair exists");
			}
			short len = pub.getExponent(buf, (short)0);
			apdu.setOutgoingAndSend((short)0, len);
			return;
		case (0x06): //request the modulus of public key
			short len = pub.getModulus(buf, (short)0);
			apdu.setOutgoingAndSend((short)0, len);
			return;
		case (0x08): //decrypt data
			if (buf[ISO7816.OFFSET_LC] = (byte)0) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			buf[4] = buf[3];
			buf[3] = buf[2];
			short len = rsa.doFinal(
				buf,
				(short) 3,
				(short) 256,
				buf,
				(short) 0
			)
			apdu.setOutgoingAndSend((short) 0, len)
			return;
		}
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);		
	}
}
