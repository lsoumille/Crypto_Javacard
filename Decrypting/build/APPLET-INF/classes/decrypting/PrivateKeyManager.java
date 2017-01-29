package decrypting;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * The KeyManager create a pair of key (private and public) in order to
 * encrypt or decrypt messages using the RSA algorithm
 * @author MK_Utilisateur
 */
public class PrivateKeyManager {

    /**
     *	Working buffers
     */
    private byte [] bufferA = null, bufferB = null;

    /**
     * Public key
     */
    private RSAPublicKey publicKey=null;

    /**
     * Private key
     */
    private RSAPrivateKey privateKey=null;

   /**
    * Crypting algorithme object
    */
   private Cipher cip=null;


    /**
     * Constructor
     */
    public PrivateKeyManager(short size) {
	bufferA = new byte[size];
	bufferB = new byte[size];

        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA,(short)(size * (short)8));
        keyPair.genKeyPair();
        publicKey = (RSAPublicKey)keyPair.getPublic();
        privateKey = (RSAPrivateKey)keyPair.getPrivate();

        cip = Cipher.getInstance(Cipher.ALG_RSA_PKCS1,false);
    }
    
        /**
     * Method to get the public key
     * @param buffer where the public key will be stored
     * @param offset index from which the public key is stored in the buffer
     * @return the length of the public key
     * @throws javacard.framework.ISOException
     */
    public short getPublicKey(byte [] buffer, short offset){
        short exponentLength;
        short modulusLength;
        exponentLength = publicKey.getExponent(buffer, (short)(offset + 2));
        Util.setShort(buffer, offset , exponentLength);
        offset += (short)(exponentLength + 2);
        modulusLength = publicKey.getModulus(buffer, (short)(offset + 2));
        Util.setShort(buffer, offset , modulusLength);
        return (short)(exponentLength + modulusLength + 4);
    }

  /**
   * Decrypt the data with the private key
   * Data are passed in an array, they are decrypted and then returned
   * in the same array, at the same place
   * @param buffer which contains the data to be decrypted
   * @param offset index from which the data are stored
   * @param length of the data to be processed
   * @return length of the decrypted data
   */
  public short decryptPrivate(byte [] buffer, short offset, short length){
      cip.init(privateKey,Cipher.MODE_DECRYPT);
      Util.arrayCopy(buffer, offset, bufferA, (short)0,length);
      length = cip.doFinal(bufferA, (short)0, length, bufferB, (short)0);
      Util.arrayCopy(bufferB, (short)0, buffer, offset, length);
      return length;
  }


}