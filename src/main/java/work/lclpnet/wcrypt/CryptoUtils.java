package work.lclpnet.wcrypt;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public class CryptoUtils {

    public static final int DEFAULT_SALT_LENGTH = 8,
            DEFAULT_IV_LENGTH = 16;

    private CryptoUtils() {}

    public static byte[] randomBytes(int n) {
        if (n < 0) throw new IllegalArgumentException("Byte count can't be negative");
        final byte[] bytes = new byte[n];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static byte[] generateSalt() {
        return randomBytes(DEFAULT_SALT_LENGTH);
    }

    public static IvParameterSpec generateIv() {
        return new IvParameterSpec(randomBytes(DEFAULT_IV_LENGTH));
    }

    public static SecretKey generateKey(int n, String algorithm) throws NoSuchAlgorithmException {
        final KeyGenerator generator = KeyGenerator.getInstance(algorithm);
        generator.init(n);

        return generator.generateKey();
    }

    public static SecretKey generateKey(String password, byte[] salt, String algorithm) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        return generateKey(password.toCharArray(), salt, algorithm);
    }

    public static SecretKey generateKey(char[] password, byte[] salt, String algorithm) throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        final KeyGeneratorInfo info = new KeyGeneratorInfo("PBKDF2WithHmacSHA256", 65536, 256);

        return generateKey(password, salt, algorithm, info);
    }

    public static SecretKey generateKey(char[] password, byte[] salt, String algorithm, KeyGeneratorInfo info)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        final SecretKeyFactory factory = SecretKeyFactory.getInstance(info.algorithm);
        final KeySpec spec = new PBEKeySpec(password, salt, info.iterations, info.keyLength);

        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);
    }

    public static Set<String> getAvailableCiphers() {
        return Arrays.stream(Security.getProviders())
                .flatMap(p -> p.getServices().stream())
                .filter(s -> "Cipher".equals(s.getType()))
                .map(Provider.Service::getAlgorithm)
                .collect(Collectors.toSet());
    }

    public static class KeyGeneratorInfo {
        public final String algorithm;
        public final int iterations, keyLength;

        public KeyGeneratorInfo(String algorithm, int iterations, int keyLength) {
            this.algorithm = algorithm;
            this.iterations = iterations;
            this.keyLength = keyLength;
        }
    }
}
