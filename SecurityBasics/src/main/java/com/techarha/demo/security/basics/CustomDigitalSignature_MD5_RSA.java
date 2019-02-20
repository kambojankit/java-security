package com.techarha.demo.security.basics;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;

@SuppressWarnings("Duplicates")
public class CustomDigitalSignature_MD5_RSA {

    private final String CHAR_SET = "UTF-8";
    private final String ALGO_KEY_TYPE = "RSA";
    private final String ALGO_SIGN_TYPE = "MD5WithRSA";
    private final String ALGO_MODE = "ECB";
    private final String ALGO_PADDING = "PKCS1Padding";
    private final Integer KEY_SIZE = 1024;
    private final String DES_CIPHER_TYPE = ALGO_KEY_TYPE + "/" + ALGO_MODE + "/" + ALGO_PADDING;

    private final KeyPair keyPair;
    private final Cipher cipher;
    private final Signature signature;

    public CustomDigitalSignature_MD5_RSA() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.keyPair = fetchKeyPair();
        this.cipher = Cipher.getInstance(DES_CIPHER_TYPE);
        this.signature = Signature.getInstance(ALGO_SIGN_TYPE);
    }

    public Boolean decryptAndVerifySignedMessage(byte[] sign, String originalInputMessage) throws UnsupportedEncodingException {
        try {
            System.out.println("Starting Signature Verification...");

            this.signature.initVerify(this.keyPair.getPublic());
            this.signature.update(originalInputMessage.getBytes(CHAR_SET));

            System.out.println("Finished Signature Verification");

            return this.signature.verify(sign);

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        System.out.println("Decryption Failed for the message: \n-----------------------------\n" + new String(sign, CHAR_SET) + "\n-----------END---------------");
        return null;
    }

    // encrypt the message digest with the RSA private key to create the signature
    public byte[] signMessage(String inputMessage) {
        try {
            this.signature.initSign(this.keyPair.getPrivate());
            this.signature.update(inputMessage.getBytes(CHAR_SET));
            byte[] signature = this.signature.sign();

            System.out.println( "Finished Signing" );
            return signature;

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
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
