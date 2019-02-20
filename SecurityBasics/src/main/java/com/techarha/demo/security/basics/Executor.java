package com.techarha.demo.security.basics;

import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class Executor {
    public static void main(String[] args) {
        try {
//            executeMessageDigestDemo();
//            executePrivateKeyEncryptionDemo();
//            executePublicKeyEncryptionDemo();
            executeCustomDigitalSignatureDemo();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void executeMessageDigestDemo() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        CustomMessageDigest customMessageDigest = new CustomMessageDigest();

        String preparedDigest1 = customMessageDigest.generateMD5FingerprintAsString("This is a Test");
        System.out.println("isValid: " +  customMessageDigest.isMessageValid("This is a Test", preparedDigest1));

        String preparedDigest2 = customMessageDigest.generateMD5FingerprintAsString("Frecko is here again");
        String preparedDigest3 = customMessageDigest.generateMD5FingerprintAsString("Get me a bloody digest");

        System.out.println("Digest Created are: "  + ", " + preparedDigest1 + " , " + preparedDigest3);
//      Why is it that the preparedDigest2 value eats up anything to be printed before. There is some issue with concatenation that needs to be looked into
//      Try the below code to know more, it has something to do with the digest generated for string "Frecko is here again"
//      System.out.println("Digest Created are: "  + ", " + preparedDigest1 + " , " + preparedDigest3);
        System.out.println( preparedDigest2 );
    }


    private static void executePrivateKeyEncryptionDemo() throws NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException {
        String plainTextMessage = "Hey this is a sample message purely intended to test Private Key encryption!!";
        PrivateKeyEncryption privateKeyEncryption = new PrivateKeyEncryption();

        byte[] encryptedMessage = privateKeyEncryption.encryptMessage(plainTextMessage);
        System.out.println("Encrypted Message is as below ... ");
        System.out.println("-----------------------------------");
        System.out.println(new String(encryptedMessage, "UTF8"));
        System.out.println("---------------END-----------------");
        System.out.println("\n");

        String decryptedMessage = privateKeyEncryption.decryptMessage(encryptedMessage);
        System.out.println("Decrypted Message is as below ... ");
        System.out.println("-----------------------------------");
        System.out.println(decryptedMessage);
        System.out.println("---------------END-----------------");
        System.out.println("\n");
    }

    private static void executePublicKeyEncryptionDemo() throws NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException {
        String plainTextMessage = "Hey this is a sample message purely intended to test Public Key encryption!!";
        PublicKeyEncryption publicKeyEncryption= new PublicKeyEncryption();

        byte[] encryptedMessage = publicKeyEncryption.encryptMessage(plainTextMessage);
        System.out.println("Encrypted Message is as below ... ");
        System.out.println("-----------------------------------");
        System.out.println(new String(encryptedMessage, "UTF8"));
        System.out.println("---------------END-----------------");
        System.out.println("\n");

        String decryptedMessage = publicKeyEncryption.decryptMessage(encryptedMessage);
        System.out.println("Decrypted Message is as below ... ");
        System.out.println("-----------------------------------");
        System.out.println(decryptedMessage);
        System.out.println("---------------END-----------------");
        System.out.println("\n");
    }

    private static void executeCustomDigitalSignatureDemo() throws NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException {
        String plainTextMessage = "Hey this is a sample message purely intended to test Digital Signature Demo!!";
        CustomDigitalSignature digitalSignature = new CustomDigitalSignature();

        byte[] encryptedMessage = digitalSignature.signMessage(plainTextMessage);
        System.out.println("Signed Message is as below ... ");
        System.out.println("-----------------------------------");
        System.out.println(new String(encryptedMessage, "UTF8"));
        System.out.println("---------------END-----------------");
        System.out.println("\n");

        Boolean isSignatureVerified = digitalSignature.decryptAndVerifySignedMessage(encryptedMessage, plainTextMessage);
        System.out.println("Signature Validation was successful? " + isSignatureVerified);
    }

    private static void executeCustomDigitalSignature_MD5_RSADemo() throws NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException {
        String plainTextMessage = "Hey this is a sample message purely intended to test Digital Signature Demo!!";
        CustomDigitalSignature_MD5_RSA digitalSignature = new CustomDigitalSignature_MD5_RSA();

        byte[] encryptedMessage = digitalSignature.signMessage(plainTextMessage);
        System.out.println("Signed Message is as below ... ");
        System.out.println("-----------------------------------");
        System.out.println(new String(encryptedMessage, "UTF8"));
        System.out.println("---------------END-----------------");
        System.out.println("\n");

        Boolean isSignatureVerified = digitalSignature.decryptAndVerifySignedMessage(encryptedMessage, plainTextMessage);
        System.out.println("Signature Validation was successful? " + isSignatureVerified);
    }
}
