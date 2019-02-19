package com.techarha.demo.security.basics;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class PrivateKeyEncryption {

    private final String CHAR_SET = "UTF-8";
    private final String ALGO_KEY_TYPE = "DES";
    private final String ALGO_MODE = "ECB";
    private final String ALGO_PADDING = "PKCS5Padding";
    private final Integer CIPHER_BLOCK_SIZE = 56;
    private final String DES_CIPHER_TYPE = ALGO_KEY_TYPE + "/" + ALGO_MODE + "/" + ALGO_PADDING;

    private final Key privateKey;
    private final Cipher cipher;

    public PrivateKeyEncryption() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.privateKey = fetchEncryptionKey();
        this.cipher = Cipher.getInstance(DES_CIPHER_TYPE);
    }

    public String decryptMessage(byte[] cipherText) {
        try {
            System.out.println("Starting decryption...");

            // initialise Cipher in Decryption mode, with the provided private key
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Decrypt Message
            byte[] plainTextStream = cipher.doFinal(cipherText);

            String plainText = new String(plainTextStream, CHAR_SET);
            System.out.println("Finished decryption");
            return plainText;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        System.out.println("Decryption Failed for the message: \n-----------------------------\n" + cipherText + "\n-----------END---------------");
        return null;
    }

    public byte[] encryptMessage(String inputMessage) {
        try {
            byte[] plainText = inputMessage.getBytes(CHAR_SET);

            // initialise Cipher in Encryption mode, with the provided private key
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);

            // Encrypt plainText into encrypted message (cipher text), using the private Key
            byte[] cipherText = cipher.doFinal(plainText);

            System.out.println( "Finished encryption" );

            return cipherText;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        System.out.println("Encryption Failed for the message: " + inputMessage);
        return null;
    }

    private Key fetchEncryptionKey() throws NoSuchAlgorithmException {
        if(this.privateKey == null ) {
            // get a DES private key
            System.out.println( "Starting generating DES key..." );
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGO_KEY_TYPE);
            keyGen.init(CIPHER_BLOCK_SIZE);
            Key key = keyGen.generateKey();
            System.out.println( "Finish generating DES key" );
            return key;
        }else {
            return privateKey;
        }
    }
}
