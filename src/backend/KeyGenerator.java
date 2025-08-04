/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package backend;

/**
 *
 * @author lapto
 */

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;



public class KeyGenerator {

    private static final String RSA = "RSA";
    private static final String SHA256_RSA = "SHA256withRSA";
    private static final String RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding";
    private static final String SHA_256 = "SHA-256";
    private static final int KEY_SIZE = 2048;

    public static KeyPair generateKeyPair(String seed) throws Exception {
        System.out.println("[KeyGenerator] Generating key pair with seed: " + seed);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.setSeed(seed.getBytes());
        keyGen.initialize(KEY_SIZE, random);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Verify the generated key pair
        if (!verifyKeyPair(keyPair)) {
            throw new Exception("Generated key pair failed verification");
        }

        System.out.println("[KeyGenerator] Key pair generated successfully");
        return keyPair;
    }

    static boolean verifyKeyPair(KeyPair keyPair) {
        try {
            System.out.println("[KeyGenerator] Verifying key pair...");
            String testData = "test123";
            String encrypted = encrypt(testData, keyPair.getPublic());
            String decrypted = decryptVote(encrypted, keyPair.getPrivate());

            boolean verified = testData.equals(decrypted);
            System.out.println("[KeyGenerator] Key pair verification: " + verified);
            return verified;
        } catch (Exception e) {
            System.err.println("[KeyGenerator] Key pair verification failed: " + e.getMessage());
            return false;
        }
    }

    public static String keyToPEM(Key key) throws Exception {
        String type = key instanceof PublicKey ? "PUBLIC KEY" : "PRIVATE KEY";
        String content = Base64.getEncoder().encodeToString(key.getEncoded());
        return String.format("-----BEGIN %s-----\n%s\n-----END %s-----\n",
                type, content, type);
    }

    public static PublicKey getPublicKeyFromPEM(String pem) throws Exception {
        System.out.println("[KeyGenerator] Parsing public key from PEM...");
        String publicKeyPEM = pem.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }

    public static PrivateKey getPrivateKeyFromPEM(String pem) throws Exception {
        System.out.println("[KeyGenerator] Parsing private key from PEM...");
        String privateKeyPEM = pem.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }

    public static String encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptVote(String encryptedVoteData, PrivateKey privateKey) throws Exception {
        try {
            String cleanData = encryptedVoteData.replaceAll("\\s", "");
            byte[] encryptedBytes = Base64.getDecoder().decode(cleanData);

            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            int chunkSize = 256;
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            for (int i = 0; i < encryptedBytes.length; i += chunkSize) {
                int length = Math.min(encryptedBytes.length - i, chunkSize);
                byte[] chunk = new byte[length];
                System.arraycopy(encryptedBytes, i, chunk, 0, length);
                byte[] decryptedChunk = cipher.doFinal(chunk);
                outputStream.write(decryptedChunk);
            }

            return new String(outputStream.toByteArray(), "UTF-8");
        } catch (Exception e) {
            System.err.println("[DECRYPT ERROR] Failed to decrypt vote: " + e.getMessage());
            throw new Exception("Decryption failed: " + e.getMessage(), e);
        }
    }

    public static String getKeyFingerprint(Key key) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(key.getEncoded());
        byte[] digest = md.digest();
        return Base64.getEncoder().encodeToString(digest).substring(0, 16);
    }

    public static String sign(String data, PrivateKey privateKey) throws Exception {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signature = sig.sign();
            return Base64.getEncoder().encodeToString(signature);
        } catch (Exception e) {
            System.err.println("[SIGN ERROR] Failed to sign data: " + e.getMessage());
            throw e;
        }
    }

    public static boolean verify(String data, String signature, PublicKey publicKey) throws Exception {
        System.out.println("[DEBUG] Verifying signature for data: " + data);
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));

            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            boolean verified = sig.verify(signatureBytes);

            System.out.println("[DEBUG] Signature verification result: " + verified);
            System.out.println("[DEBUG] Used public key: " + publicKey.toString());
            return verified;
        } catch (Exception e) {
            System.err.println("[VERIFY ERROR] Verification failed: " + e.getMessage());
            throw e;
        }
    }

    public static String hashData(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data.getBytes("UTF-8"));
        byte[] digest = md.digest();
        return Base64.getEncoder().encodeToString(digest);
    }

    public static boolean compareHashes(String calculatedBase64, String receivedHash) {
        try {
            String calculatedHex = base64ToHex(calculatedBase64);
            String normalizedReceived = receivedHash.replaceAll("[^0-9a-fA-F]", "").toLowerCase();
            return calculatedHex.equals(normalizedReceived);
        } catch (Exception e) {
            System.err.println("[HASH ERROR] Comparison failed: " + e.getMessage());
            return false;
        }
    }

    private static String base64ToHex(String base64) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(base64);
        StringBuilder hex = new StringBuilder();
        for (byte b : decoded) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    public static String hashDataToHex(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data.getBytes("UTF-8"));
        byte[] digest = md.digest();

        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public static String keyToString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PrivateKey getPrivateKeyFromString(String pem) throws Exception {
        System.out.println("\n[KeyGenerator] Parsing private key...");
        System.out.println("[KeyGenerator] Input length: " + pem.length());

        try {
            String privateKeyPEM = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            System.out.println("[KeyGenerator] Cleaned PEM length: " + privateKeyPEM.length());
            System.out.println("[KeyGenerator] First 50 chars: " + privateKeyPEM.substring(0, Math.min(50, privateKeyPEM.length())));

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            System.out.println("[KeyGenerator] Decoded byte length: " + encoded.length);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);

            System.out.println("[KeyGenerator] Key spec created successfully");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            System.out.println("[KeyGenerator ERROR] Failed parsing private key");
            e.printStackTrace();
            throw e;
        }
    }

    public static PublicKey getPublicKeyFromString(String pem) throws Exception {
        System.out.println("\n[KeyGenerator] Parsing public key...");
        System.out.println("[KeyGenerator] Input length: " + pem.length());

        try {
            String publicKeyPEM = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            System.out.println("[KeyGenerator] Cleaned PEM length: " + publicKeyPEM.length());
            System.out.println("[KeyGenerator] First 50 chars: " + publicKeyPEM.substring(0, Math.min(50, publicKeyPEM.length())));

            byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
            System.out.println("[KeyGenerator] Decoded byte length: " + encoded.length);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);

            System.out.println("[KeyGenerator] Key spec created successfully");
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            System.out.println("[KeyGenerator ERROR] Failed parsing public key");
            e.printStackTrace();
            throw e;
        }
    }
}
