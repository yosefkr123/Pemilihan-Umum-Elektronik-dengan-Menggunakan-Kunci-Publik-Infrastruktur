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
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.MessageDigest;

public class CryptoUtils {

    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";

    // Get AES key from environment variable or config
    private static byte[] getAesKey() throws Exception {
        String keyStr = System.getenv("AES_SECRET_KEY");
        if (keyStr == null || keyStr.length() < 16) {
            throw new Exception("Invalid AES key configuration");
        }

        // Use SHA-256 to ensure proper key length
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(keyStr.getBytes("UTF-8"));
    }

    public static String decrypt(String encryptedData) throws Exception {
        try {
            SecretKeySpec key = new SecretKeySpec(getAesKey(), "AES");
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decoded = Base64.getDecoder().decode(encryptedData);
            return new String(cipher.doFinal(decoded), "UTF-8");
        } catch (Exception e) {
            throw new Exception("Decryption failed: " + e.getMessage());
        }
    }
}
