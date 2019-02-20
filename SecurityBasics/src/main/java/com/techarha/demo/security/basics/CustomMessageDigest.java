package com.techarha.demo.security.basics;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public class CustomMessageDigest {

    private final String CHAR_SET = "UTF-8";

    private final MessageDigest messageDigest;

    public CustomMessageDigest() throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance("MD5");
    }

    public byte[] generateMD5Fingerprint(String message) throws UnsupportedEncodingException {
        // reset digest
        messageDigest.reset();

        byte[] plainText = message.getBytes(this.CHAR_SET);

        // Fetch the provider for the messageDigest
        Provider mdProvider = messageDigest.getProvider();
        System.out.println( "Message Digest Provider: " + mdProvider.getInfo() );

        // setup the message, to prepare a digest for..
        messageDigest.update(plainText);

        // fetch the prepared digest
        String mdFingerprint = new String(messageDigest.digest(), CHAR_SET);
        System.out.println("generated digest: " + mdFingerprint);
        return messageDigest.digest();
    }

    public String generateMD5FingerprintAsString(String message) throws UnsupportedEncodingException {
        return new String(generateMD5Fingerprint(message), CHAR_SET);
    }

    public Boolean isMessageValid(String message, String actualDigest) throws UnsupportedEncodingException {
        byte[] expectedDigest = generateMD5Fingerprint(message);

        return actualDigest.equals(new String(expectedDigest, CHAR_SET));
    }
}
