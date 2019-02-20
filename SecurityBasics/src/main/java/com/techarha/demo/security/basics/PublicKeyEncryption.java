package com.techarha.demo.security.basics;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class PublicKeyEncryption {

    private final String CHAR_SET = "UTF-8";
    private final String ALGO_KEY_TYPE = "RSA";
    private final String ALGO_MODE = "ECB";
    private final String ALGO_PADDING = "PKCS1Padding";
    private final Integer KEY_SIZE = 1024;
    private final String DES_CIPHER_TYPE = ALGO_KEY_TYPE + "/" + ALGO_MODE + "/" + ALGO_PADDING;

    private final KeyPair keyPair;
    private final Cipher cipher;

    public PublicKeyEncryption() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.keyPair = fetchKeyPair();
        this.cipher = Cipher.getInstance(DES_CIPHER_TYPE);
    }

    public String decryptMessage(byte[] cipherText) {
        try {
            System.out.println("Starting decryption...");

            // initialise Cipher in Decryption mode, with the provided private key
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

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
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

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

    private KeyPair fetchKeyPair() throws NoSuchAlgorithmException {
        if(this.keyPair == null ) {
            // get a DES private key
            System.out.println( "Starting generating RSA key Pair..." );
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGO_KEY_TYPE);
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            System.out.println( "Finish generating RSA key pair" );
            return keyPair;
        }else {
            return this.keyPair;
        }
    }
}
