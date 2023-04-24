package classicapplet1;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/*
 * All variables and methods names are derived from CARD point of view.
 * incomingData means data that are incoming INTO card sendName() sends name
 * FROM card into terminal etc...
 */
public class ClassicApplet1 extends Applet {

    // code of CLA byte in the command APDU header
    final static byte CardApplet_CLA = (byte) 0x80;

    // codes of INS byte for CardApplet_CLA in the command APDU header
    final static byte SEND_NAME = (byte) 0x00;
    final static byte GET_DATA = (byte) 0x02;
    final static byte SEND_RECEIVED_DATA = (byte) 0x04;
    final static byte VERIFY = (byte) 0x20;
    final static byte GET_ENCRYPT_SEND = (byte) 0x42;
    final static byte GET_DECRYPT_SEND = (byte) 0x44;

    // maximum number of incorrect tries before the PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    // signal the the PIN validation is required
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    // signal that card is blocked after max PIN tries (TODO what is the code?)
    final static short SW_CARD_BLOCKED = 0x6302;
    

    // name to return used in INS 0x00
    final static byte[] NAME_STRING = {'M', 'a', 't', 'u', 's'};
   
    final static byte[] AES_ENC_KEY =
        {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25};
    
    final static byte[] AES_SIGN_KEY =
        {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
         0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45};
    
    // Instance variables
    byte[] incomingData;
    short incomingDataSize;
    byte[] receivedPin;    
    OwnerPIN pin;
    AESKey key_enc;
    AESKey key_mac;
    Cipher aes_enc;
    Signature aes_mac;

    /**
     * Installs this applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ClassicApplet1(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    private ClassicApplet1(byte[] bArray, short bOffset, byte bLength) {        
        incomingData = new byte[20];
        incomingDataSize = (short) 0;        
        
        receivedPin = new byte[MAX_PIN_SIZE];
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE); // instanciuj objekt pin
        
        key_enc = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        key_enc.setKey(AES_ENC_KEY, (short)0);
        key_mac = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        key_mac.setKey(AES_SIGN_KEY, (short)0);
        aes_enc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);        
        aes_mac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
        
        
        

        // check incoming parameter data
        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length
        bOffset++;
        pin.update(bArray, bOffset, aLen); // nastav pociatocne heslo               
        
        register();
    }

    public boolean select() {
        // The applet declines to be selected
        // if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }
        return true;
    }

    public void deselect() {
        // reset the pin value
        pin.reset();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu the incoming APDU
     */
    public void process(APDU apdu) {
        if (selectingApplet()) {
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
        
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_CARD_BLOCKED);
        }

        byte[] buf = apdu.getBuffer();
        byte _CLA = buf[ISO7816.OFFSET_CLA];
        byte _INS = buf[ISO7816.OFFSET_INS];

        if (_CLA != CardApplet_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (_INS) {
            case SEND_NAME:
                sendName(apdu);
                break;

            case GET_DATA:
                validate();
                getData(apdu);
                break;

            case SEND_RECEIVED_DATA:
                validate();
                sendReceivedData(apdu);
                break;
                
            case VERIFY:
                verify(apdu);
                break;
                
            case GET_ENCRYPT_SEND:
                validate();
                getEncryptSend(apdu);
                break;
                
            case GET_DECRYPT_SEND:
                validate();
                getDecryptSend(apdu);
                break;            

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // INS 0x00
    private void sendName(APDU apdu) {
        short _Le = apdu.setOutgoing();
        if (_Le > NAME_STRING.length) {
            _Le = (short) NAME_STRING.length;
        }
        apdu.setOutgoingLength(_Le); // outgoing with correct 'Le' set
        apdu.sendBytesLong(NAME_STRING, (short) 0, _Le);
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    // INS 0x02
    private void getData(APDU apdu) {
        short _Lc = apdu.setIncomingAndReceive(); // actual received data length stored to 'Lc'
        if (_Lc > (short) 20) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, incomingData, (short) 0, _Lc);
        incomingDataSize = _Lc;
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    // INS 0x04
    // needs getData() to be called first
    private void sendReceivedData(APDU apdu) {
        short _Le = apdu.setOutgoing();
        if (_Le != incomingDataSize) {
            ISOException.throwIt((short) (ISO7816.SW_CORRECT_LENGTH_00 + incomingDataSize));
        }
        apdu.setOutgoingLength(_Le);
        apdu.sendBytesLong(incomingData, (short) 0, _Le);
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    // INS 0x20
    private void verify(APDU apdu) {
        byte pinSize = (byte) apdu.setIncomingAndReceive(); // Lc        
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, receivedPin, (short) 0, pinSize);

        boolean match = pin.check(receivedPin, (short) 0, (byte) pinSize);
        if (match) {
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        } else {            
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    }
    
    // INS 0x42
    private void getEncryptSend(APDU apdu) {
        short _Lc = apdu.setIncomingAndReceive();
        // Trivial situation solved here so we don't need to do crypto
        // operations if they are not needed at all.
        if (_Lc > (short) 64) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        } else if ( (_Lc % 16) != 0) {
            ISOException.throwIt((short)
                    (ISO7816.SW_WRONG_LENGTH + CryptoException.ILLEGAL_USE));
        }
        
        // Initialize crypto objects for encrypting
        aes_enc.init(key_enc, Cipher.MODE_ENCRYPT);
        aes_mac.init(key_mac, Signature.MODE_SIGN);               
        
        try {
            // Save encrypted message into APDU buffer from beginning
            short encLen = aes_enc.doFinal(apdu.getBuffer(), ISO7816.OFFSET_CDATA, _Lc, apdu.getBuffer(), (short)0);
            // Append MAC into APDU after encrypted message
            short macLen = aes_mac.sign(apdu.getBuffer(), (short)0, encLen, apdu.getBuffer(), encLen);            
            
            apdu.setOutgoingAndSend((short)0, (short)(encLen + macLen));
        } catch(CryptoException e) {
            if (e.getReason() == CryptoException.ILLEGAL_USE) {
                ISOException.throwIt((short)
                        (ISO7816.SW_WRONG_LENGTH + CryptoException.ILLEGAL_USE));
            }
            ISOException.throwIt((short) (ISO7816.SW_UNKNOWN + e.getReason()));
        }
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
    
    
    // INS 0x44
    private void getDecryptSend(APDU apdu) {
        short _Lc = apdu.setIncomingAndReceive();
        // Trivial situation solved here so we don't need to do crypto
        // operations if they are not needed at all.
        if (_Lc > (short)80) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        } else if ( (_Lc % 16) != 0) {
            ISOException.throwIt((short)
                    (ISO7816.SW_WRONG_LENGTH + CryptoException.ILLEGAL_USE));
        }
        
        // Initialize crypto objects for decrypting
        aes_enc.init(key_enc, Cipher.MODE_DECRYPT);
        aes_mac.init(key_mac, Signature.MODE_VERIFY);
        
        try {
            boolean isVerified = aes_mac.verify(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (short)(_Lc - 16), apdu.getBuffer(), (short)(ISO7816.OFFSET_CDATA + _Lc - 16), (short)16);
            if (!isVerified) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        } catch(CryptoException e) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        
        try {
            // Save decrypted message into APDU buffer from beginning
            short decLen = aes_enc.doFinal(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (short)(_Lc - 16), apdu.getBuffer(), (short)0);
            
            apdu.setOutgoingAndSend((short)0, decLen);
        } catch(CryptoException e) {
            if (e.getReason() == CryptoException.ILLEGAL_USE) {
                ISOException.throwIt((short)
                        (ISO7816.SW_WRONG_LENGTH + CryptoException.ILLEGAL_USE));
            }
            ISOException.throwIt((short) (ISO7816.SW_UNKNOWN + e.getReason()));
        }
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
    
    // Use to validate PIN for INS to continue progressing
    private void validate() {
        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
    }
}
