package work.lclpnet.wcrypt;

import org.junit.jupiter.api.Test;
import work.lclpnet.wcrypt.aes.AESCrypto;
import work.lclpnet.wcrypt.cipher.IVCipher;
import work.lclpnet.wcrypt.cipher.SimpleCipher;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptoManagerTest {

    public static final String CONTENT = "Hello World.";

    @Test
    void decryptIn() throws GeneralSecurityException, IOException {
        SecretKey key = AESCrypto.generateKey("test123", TestHelper.readSalt());
        CryptoManager crypto = new CryptoManager(key);

        byte[] bytes;
        try (InputStream in = crypto.decrypt(TestHelper.getJarResource("/content.enc"));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[1024];
            int read;

            while((read = in.read(buffer)) != -1)
                out.write(buffer, 0, read);

            bytes = out.toByteArray();
        }

        assertEquals(CONTENT, new String(bytes, StandardCharsets.UTF_8));
    }

    @Test
    void encryptOutSmallerThanBuffer() throws GeneralSecurityException, IOException {
        SecretKey key = AESCrypto.generateKey("test123", TestHelper.readSalt());
        CryptoManager crypto = new CryptoManager(key);

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = crypto.encrypt(encOut);

        out.write(CONTENT.getBytes(StandardCharsets.UTF_8));
        out.close();
        encOut.close();

        byte[] encBytes = encOut.toByteArray();
        byte[] iv = new byte[CryptoUtils.DEFAULT_IV_LENGTH];
        System.arraycopy(encBytes, 0, iv, 0, iv.length);

        IVCipher cipher = AESCrypto.createCipher(key, new IvParameterSpec(iv));
        cipher.begin(SimpleCipher.Mode.DECRYPT);
        byte[] decryptedBytes = cipher.doFinal(encBytes, CryptoUtils.DEFAULT_IV_LENGTH,
                encBytes.length - CryptoUtils.DEFAULT_IV_LENGTH);

        assertEquals(CONTENT, new String(decryptedBytes, StandardCharsets.UTF_8));
    }

    @Test
    void encryptOutBiggerThanBuffer() throws GeneralSecurityException, IOException {
        SecretKey key = AESCrypto.generateKey("test123", TestHelper.readSalt());
        CryptoManager crypto = new CryptoManager(key);

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = crypto.encrypt(encOut);

        final byte[] expected = CryptoUtils.randomBytes(1025);

        out.write(expected);
        out.close();
        encOut.close();

        byte[] encBytes = encOut.toByteArray();
        byte[] iv = new byte[CryptoUtils.DEFAULT_IV_LENGTH];
        System.arraycopy(encBytes, 0, iv, 0, iv.length);

        IVCipher cipher = AESCrypto.createCipher(key, new IvParameterSpec(iv));
        cipher.begin(SimpleCipher.Mode.DECRYPT);
        byte[] decryptedBytes = cipher.doFinal(encBytes, CryptoUtils.DEFAULT_IV_LENGTH,
                encBytes.length - CryptoUtils.DEFAULT_IV_LENGTH);

        assertArrayEquals(expected, decryptedBytes);
    }

    @Test
    void encryptOutMultiOffset() throws GeneralSecurityException, IOException {
        SecretKey key = AESCrypto.generateKey("test123", TestHelper.readSalt());
        CryptoManager crypto = new CryptoManager(key);

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = crypto.encrypt(encOut);

        final byte[] expected = CryptoUtils.randomBytes(700 * 3);

        out.write(expected, 0, 700);
        out.write(expected, 700, 700);
        out.write(expected, 700 * 2, 700);

        out.close();
        encOut.close();

        byte[] encBytes = encOut.toByteArray();
        byte[] iv = new byte[CryptoUtils.DEFAULT_IV_LENGTH];
        System.arraycopy(encBytes, 0, iv, 0, iv.length);

        IVCipher cipher = AESCrypto.createCipher(key, new IvParameterSpec(iv));
        cipher.begin(SimpleCipher.Mode.DECRYPT);
        byte[] decryptedBytes = cipher.doFinal(encBytes, CryptoUtils.DEFAULT_IV_LENGTH,
                encBytes.length - CryptoUtils.DEFAULT_IV_LENGTH);

        assertArrayEquals(expected, decryptedBytes);
    }

    @Test
    void getKey() throws NoSuchAlgorithmException {
        SecretKey key = AESCrypto.generateKey(128);
        CryptoManager crypto = new CryptoManager(key);
        assertEquals(key, crypto.getKey());
    }

    @Test
    void encryptDecryptStreams() throws GeneralSecurityException, IOException {
        SecretKey key = AESCrypto.generateKey("test123", TestHelper.readSalt());
        CryptoManager crypto = new CryptoManager(key);

        byte[] enc;
        try (ByteArrayInputStream in = new ByteArrayInputStream(CONTENT.getBytes(StandardCharsets.UTF_8));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            crypto.encrypt(in, out);
            enc = out.toByteArray();
        }

        byte[] res;
        try (ByteArrayInputStream in = new ByteArrayInputStream(enc);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            crypto.decrypt(in, out);
            res = out.toByteArray();
        }

        assertEquals(CONTENT, new String(res, StandardCharsets.UTF_8));
    }

    @Test
    void encryptDecryptBytes() throws GeneralSecurityException, IOException {
        SecretKey key = AESCrypto.generateKey("test123", TestHelper.readSalt());
        CryptoManager crypto = new CryptoManager(key);

        byte[] encrypted = crypto.encrypt(CONTENT.getBytes(StandardCharsets.UTF_8));
        byte[] decrypted = crypto.decrypt(encrypted);

        assertEquals(CONTENT, new String(decrypted, StandardCharsets.UTF_8));
    }
}