package work.lclpnet.wcrypt.aes;

import work.lclpnet.wcrypt.CryptoUtils;
import work.lclpnet.wcrypt.cipher.CipherProvider;
import work.lclpnet.wcrypt.cipher.IVCipher;
import work.lclpnet.wcrypt.cipher.IvCipherImpl;

import javax.annotation.Nullable;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class AESCrypto {

    public static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final CipherProvider PROVIDER = AESCrypto::createCipher;

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        return CryptoUtils.generateKey(n, "AES");
    }

    public static SecretKey generateKey(String password, byte[] salt) throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        return CryptoUtils.generateKey(password, salt, "AES");
    }

    public static IVCipher createCipher(SecretKey key) {
        return new IvCipherImpl(ALGORITHM, key);
    }

    public static IVCipher createCipher(SecretKey key, @Nullable IvParameterSpec iv) {
        return new IvCipherImpl(ALGORITHM, key, iv);
    }

    public static String encrypt(String input, SecretKey key, IvParameterSpec iv) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {

        final Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        final byte[] cipherText = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, SecretKey key, IvParameterSpec iv) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {

        final Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        final byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));

        return new String(plainText, StandardCharsets.UTF_8);
    }
}
