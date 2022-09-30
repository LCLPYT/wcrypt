package work.lclpnet.wcrypt;

import work.lclpnet.wcrypt.aes.AESCrypto;
import work.lclpnet.wcrypt.cipher.BufferedCipherOutputStream;
import work.lclpnet.wcrypt.cipher.CipherProvider;
import work.lclpnet.wcrypt.cipher.IVCipher;
import work.lclpnet.wcrypt.cipher.SimpleCipher;

import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

public class CryptoManager {

    private final SecretKey key;
    private final CipherProvider provider;

    public CryptoManager(SecretKey key) {
        this(key, AESCrypto.PROVIDER);
    }

    public CryptoManager(SecretKey key, CipherProvider provider) {
        this.key = key;
        this.provider = provider;
    }

    public SecretKey getKey() {
        return key;
    }

    public InputStream decrypt(InputStream input) throws GeneralSecurityException, IOException {
        SimpleCipher cipher = provider.provide(key);

        if (cipher instanceof IVCipher) {
            final byte[] iv = new byte[CryptoUtils.DEFAULT_IV_LENGTH];
            if (input.read(iv) == -1) throw new IOException("Initialization vector not found");

            ((IVCipher) cipher).setIv(new IvParameterSpec(iv));
        }

        cipher.begin(SimpleCipher.Mode.DECRYPT);

        return new CipherInputStream(input, cipher.getCipher());
    }

    public OutputStream encrypt(OutputStream output) throws GeneralSecurityException, IOException {
        return encrypt(output, 1024);
    }

    public OutputStream encrypt(OutputStream output, int bufferSize) throws GeneralSecurityException, IOException {
        SimpleCipher cipher = provider.provide(key);
        cipher.begin(SimpleCipher.Mode.ENCRYPT);

        if (cipher instanceof IVCipher) {
            final IvParameterSpec iv = ((IVCipher) cipher).getIv();
            if (iv != null) output.write(iv.getIV());
        }

        return new BufferedCipherOutputStream(output, cipher.getCipher(), bufferSize);
    }

    public void decrypt(InputStream cipherTextIn, OutputStream plainTextOut) throws GeneralSecurityException, IOException {
        SimpleCipher cipher = provider.provide(key);

        if (cipher instanceof IVCipher) {
            final byte[] iv = new byte[CryptoUtils.DEFAULT_IV_LENGTH];
            if (cipherTextIn.read(iv) == -1) throw new IOException("Initialization vector not found");

            ((IVCipher) cipher).setIv(new IvParameterSpec(iv));
        }

        cipher.begin(SimpleCipher.Mode.DECRYPT);

        byte[] encBuffer = new byte[1024];
        byte[] buffer;
        int read;

        while ((read = cipherTextIn.read(encBuffer)) != -1) {
            if (read < encBuffer.length) {
                buffer = cipher.doFinal(encBuffer, 0, read);
            } else {
                buffer = cipher.update(encBuffer, 0, read);
            }

            plainTextOut.write(buffer, 0, buffer.length);
        }
    }

    public void encrypt(InputStream plainTextIn, OutputStream cipherTextOut) throws GeneralSecurityException, IOException {
        SimpleCipher cipher = provider.provide(key);
        cipher.begin(SimpleCipher.Mode.ENCRYPT);

        if (cipher instanceof IVCipher) {
            final IvParameterSpec iv = ((IVCipher) cipher).getIv();
            if (iv != null) cipherTextOut.write(iv.getIV());
        }

        byte[] buffer = new byte[1024];
        byte[] encBuffer;
        int read;

        while ((read = plainTextIn.read(buffer)) != -1) {
            if (read < buffer.length) {
                encBuffer = cipher.doFinal(buffer, 0, read);
            } else {
                encBuffer = cipher.update(buffer, 0, read);
            }

            cipherTextOut.write(encBuffer, 0, encBuffer.length);
        }
    }

    public byte[] decrypt(byte[] cipherText) throws GeneralSecurityException {
        SimpleCipher cipher = provider.provide(key);

        if (cipher instanceof IVCipher) {
            final byte[] iv = new byte[CryptoUtils.DEFAULT_IV_LENGTH];
            System.arraycopy(cipherText, 0, iv, 0, iv.length);

            ((IVCipher) cipher).setIv(new IvParameterSpec(iv));
        }

        cipher.begin(SimpleCipher.Mode.DECRYPT);
        return cipher.doFinal(cipherText, CryptoUtils.DEFAULT_IV_LENGTH,
                cipherText.length - CryptoUtils.DEFAULT_IV_LENGTH);
    }

    public byte[] encrypt(byte[] plainText) throws GeneralSecurityException {
        SimpleCipher cipher = provider.provide(key);
        cipher.begin(SimpleCipher.Mode.ENCRYPT);

        final byte[] encrypted = cipher.doFinal(plainText);

        if (cipher instanceof IVCipher) {
            final IvParameterSpec ivSpec = ((IVCipher) cipher).getIv();
            if (ivSpec != null) {
                final byte[] iv = ivSpec.getIV();
                final byte[] out = new byte[encrypted.length + iv.length];

                System.arraycopy(iv, 0, out, 0, iv.length);
                System.arraycopy(encrypted, 0, out, iv.length, encrypted.length);

                return out;
            }
        }

        return encrypted;
    }
}
