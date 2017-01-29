package encrypting;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * The KeyManager create a pair of key (private and public) in order to
 * encrypt or decrypt messages using the RSA algorithm
 * @author MK_Utilisateur
 */
public class PublicKeyManager {

    /**
     *	Working buffers
     */
    private byte [] bufferA = null, bufferB = null;

    /**
     * Public key
     */
    private RSAPublicKey publicKey=null;

    
   /**
    * Crypting algorithme object
    */
   private Cipher cip=null;


    /**
     * Constructor
     */
    public PublicKeyManager(short size) {
	bufferA = new byte[size];
	bufferB = new byte[size];

        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA,(short)(size * (short)8));
        keyPair.genKeyPair();
        publicKey = (RSAPublicKey)keyPair.getPublic();

        cip = Cipher.getInstance(Cipher.ALG_RSA_PKCS1,false);
    }
    

  /**
   * Encrypt the data with the public key
   * Data are passed in an array, they are encrypted and then returned
   * in the same array, at the same place
   * @param buffer which contains the data to be encrypted
   * @param offset index from which the data are stored
   * @param length of the data to be processed
   * @return length of the encrypted data
   */
  public short encryptPublic(byte [] buffer, short offset, short length){
      cip.init(publicKey,Cipher.MODE_ENCRYPT);
      Util.arrayCopy(buffer, offset, bufferA, (short)0,length);
      length = cip.doFinal(bufferA, (short)0, length, bufferB, (short)0);
      Util.arrayCopy(bufferB, (short)0, buffer, offset, length);
      return length;
  }
  
    /**
     * Method to get the public key
     * @param buffer where the public key will be stored
     * @param offset index from which the public key is stored in the buffer
     * @return the length of the public key
     * @throws javacard.framework.ISOException
     */
    public void setPublicKey(byte [] buffer, short offset){
        short exponentLength;
        short modulusLength;
        exponentLength = Util.getShort(buffer, offset);
        publicKey.setExponent(buffer, (short)(offset + 2), exponentLength);
        offset += (short)(exponentLength + 2);
        modulusLength = Util.getShort(buffer, offset);
        publicKey.setModulus(buffer, (short)(offset + 2), modulusLength);
    }

}