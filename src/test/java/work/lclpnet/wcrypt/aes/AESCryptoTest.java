package work.lclpnet.wcrypt.aes;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import work.lclpnet.wcrypt.CryptoUtils;
import work.lclpnet.wcrypt.cipher.IVCipher;
import work.lclpnet.wcrypt.cipher.SimpleCipher;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static work.lclpnet.wcrypt.aes.AESCrypto.*;

class AESCryptoTest {

    private static final String TEST_CONTENT = "Hello World.",
            TEST_PW = "test123";

    @ParameterizedTest
    @MethodSource("keys")
    void testEncryptDecrypt(final SecretKey key) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        final String input = "Hello World";
        final IvParameterSpec iv = CryptoUtils.generateIv();

        final String cipherText = encrypt(input, key, iv);
        final String plainText = decrypt(cipherText, key, iv);

        assertEquals(input, plainText);
    }

    @ParameterizedTest
    @MethodSource("keys")
    void testCipherImmediately(final SecretKey key) throws GeneralSecurityException {
        final String input = "Hello World";

        IVCipher cipher = AESCrypto.createCipher(key);

        cipher.begin(SimpleCipher.Mode.ENCRYPT);
        byte[] cipherBytes = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));

        cipher.begin(SimpleCipher.Mode.DECRYPT);
        byte[] plainTextBytes = cipher.doFinal(cipherBytes);

        final String plainText = new String(plainTextBytes, StandardCharsets.UTF_8);
        assertEquals(input, plainText);
    }

    @ParameterizedTest
    @MethodSource("keys")
    void testCipherStream(final SecretKey key) throws GeneralSecurityException, IOException {
        IVCipher cipher = AESCrypto.createCipher(key);

        final byte[] cipherBytes;
        try (InputStream in = getClass().getResourceAsStream("/plain.txt");
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            cipher.begin(SimpleCipher.Mode.ENCRYPT);
            cipher.transfer(in, out);

            cipherBytes = out.toByteArray();
        }

        try (ByteArrayInputStream in = new ByteArrayInputStream(cipherBytes);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            cipher.begin(SimpleCipher.Mode.DECRYPT);
            cipher.transfer(in, out);

            final byte[] plainTextBytes = out.toByteArray();
            final String plainText = new String(plainTextBytes, StandardCharsets.UTF_8);

            final String expected = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua.\n" +
                    "At vero eos et accusam et justo duo dolores et ea rebum.";

            assertEquals(expected, plainText);
        }
    }

    @Test
    void writeEncryptedFile() throws IOException, GeneralSecurityException {
        Path encPath = Paths.get("run", "content.enc");
        if (Files.exists(encPath.getParent())) {
            Files.createDirectories(encPath.getParent());
        }

        final byte[] salt = CryptoUtils.generateSalt();
        SecretKey key = AESCrypto.generateKey(TEST_PW, salt);

        IVCipher cipher = AESCrypto.createCipher(key);
        cipher.begin(SimpleCipher.Mode.ENCRYPT);

        try (OutputStream out = new FileOutputStream(encPath.toFile())) {
            final IvParameterSpec iv = cipher.getIv();
            if (iv == null) throw new IllegalStateException();

            out.write(iv.getIV());

            byte[] cipherBytes = cipher.doFinal(TEST_CONTENT.getBytes(StandardCharsets.UTF_8));
            out.write(cipherBytes);
        }

        Path keyPath = Paths.get("run", "content.enc.salt");
        try (OutputStream out = new FileOutputStream(keyPath.toFile())) {
            out.write(salt);
        }
    }

    @Test
    void readEncryptedFile() throws IOException, GeneralSecurityException {
        byte[] salt;
        try (InputStream in = getClass().getResourceAsStream("/content.enc.salt");
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            assertNotNull(in);

            byte[] buffer = new byte[1024];
            int read;

            while ((read = in.read(buffer)) != -1)
                out.write(buffer, 0, read);

            salt = out.toByteArray();
        }

        try (InputStream in = getClass().getResourceAsStream("/content.enc");
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            assertNotNull(in);

            byte[] iv = new byte[CryptoUtils.DEFAULT_IV_LENGTH];
            assertNotEquals(-1, in.read(iv));

            SecretKey key = AESCrypto.generateKey(TEST_PW, salt);
            IVCipher cipher = AESCrypto.createCipher(key, new IvParameterSpec(iv));
            cipher.begin(SimpleCipher.Mode.DECRYPT);

            cipher.transfer(in, out);

            String plainText = new String(out.toByteArray(), StandardCharsets.UTF_8);
            assertEquals(TEST_CONTENT, plainText);
        }
    }

    private static Stream<SecretKey> keys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Stream.of(
                generateKey("mypasswd", CryptoUtils.generateSalt()),
                generateKey(256)
        );
    }
}