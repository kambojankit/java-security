package com.techarha.demo.security.basics;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public class MessageDigestDemo {

    private final String CHAR_SET = "UTF-8";

    private final MessageDigest messageDigest;

    public MessageDigestDemo() throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance("MD5");
    }

    public String generateMD5Fingerprint(String message) throws UnsupportedEncodingException {
        byte[] plainText = message.getBytes(this.CHAR_SET);

        // Fetch the provider for the messageDigest
        Provider mdProvider = messageDigest.getProvider();
        System.out.println( "Message Digest Provider: " + mdProvider.getInfo() );

        // setup the message, to prepare a digest for..
        messageDigest.update(plainText);

        // fetch the prepared digest
        String mdFingerprint = new String(messageDigest.digest(), CHAR_SET);

        return mdFingerprint;
    }

    public Boolean isMessageValid(String message, String actualDigest) throws UnsupportedEncodingException {
        String expectedDigest = generateMD5Fingerprint(message);

        return actualDigest.equals(expectedDigest);
    }
}
