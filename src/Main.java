import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        SecureRandom secureRandom = new SecureRandom();
//        keyGenerator.init(256, secureRandom);
//        SecretKey secretKey = keyGenerator.generateKey();
//        String base64Key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
//        System.out.println(base64Key);
        String s = "Hello World!";

        String encryptedData = CryptoUtils.encrypt(s);
        System.out.println(encryptedData);

        String decryptedData = CryptoUtils.decrypt(encryptedData);
        System.out.println(decryptedData);
    }
}
