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

@SuppressWarnings("Duplicates")
public class CustomDigitalSignature {

    private final String CHAR_SET = "UTF-8";
    private final String ALGO_KEY_TYPE = "RSA";
    private final String ALGO_MODE = "ECB";
    private final String ALGO_PADDING = "PKCS1Padding";
    private final Integer KEY_SIZE = 1024;
    private final String DES_CIPHER_TYPE = ALGO_KEY_TYPE + "/" + ALGO_MODE + "/" + ALGO_PADDING;

    private final KeyPair keyPair;
    private final Cipher cipher;
    private final CustomMessageDigest messageDigest;

    public CustomDigitalSignature() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.keyPair = fetchKeyPair();
        this.cipher = Cipher.getInstance(DES_CIPHER_TYPE);
        this.messageDigest = new CustomMessageDigest();

    }

    public Boolean decryptAndVerifySignedMessage(byte[] cipherText, String originalInputMessage) throws UnsupportedEncodingException {
        try {
            System.out.println("Starting Signature Verification...");

            // initialise Cipher in Decryption mode, with the provided private key
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());

            // Decrypt Message
            byte[] newMessageDigest = cipher.doFinal(cipherText);

            // Re-generate message digest for the provided original message
            byte[] generatedOriginalMessageDigest = this.messageDigest.generateMD5Fingerprint(originalInputMessage);

            // Verify both MessageDigests are equal
            Boolean isSignatureVerified = verifyMessageDigests(generatedOriginalMessageDigest, newMessageDigest);

            System.out.println("Finished Signature Verification");


            return isSignatureVerified;


        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        System.out.println("Decryption Failed for the message: \n-----------------------------\n" + new String(cipherText, CHAR_SET) + "\n-----------END---------------");
        return null;
    }

    // encrypt the message digest with the RSA private key to create the signature
    public byte[] signMessage(String inputMessage) {
        try {
            byte[] generatedMessageDigest = extractMessageDigest(inputMessage);

            // initialise Cipher in Encryption mode, with the provided private key
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());

            // Encrypt plainText into encrypted message (cipher text), using the private Key
            byte[] cipherText = cipher.doFinal(generatedMessageDigest);

            System.out.println( "Finished Signing" );
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

        System.out.println("Signing Failed for the message: " + inputMessage);
        return null;
    }

    private Boolean verifyMessageDigests(byte[] oldMessageDigest, byte[] newMessageDigest) {
        int newMDLen = newMessageDigest.length;
        if (newMDLen > oldMessageDigest.length) {
            System.out.println( "Signature failed, length error");
            return false;
        }
        for (int i = 0; i < newMDLen; ++i) {
            if (oldMessageDigest[i] != newMessageDigest[i]) {
                System.out.println("Signature failed, element error");
                return false;
            }
        }

        return true;
    }

    private byte[] extractMessageDigest(String inputMessage) throws UnsupportedEncodingException {
        return this.messageDigest.generateMD5Fingerprint(inputMessage);
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
