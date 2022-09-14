package work.lclpnet.wcrypt;

import work.lclpnet.wcrypt.aes.AESCrypto;
import work.lclpnet.wcrypt.cipher.CipherProvider;
import work.lclpnet.wcrypt.cipher.IVCipher;
import work.lclpnet.wcrypt.cipher.SimpleCipher;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
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
        SimpleCipher cipher = provider.provide(key);
        cipher.begin(SimpleCipher.Mode.DECRYPT);

        if (cipher instanceof IVCipher) {
            final IvParameterSpec iv = ((IVCipher) cipher).getIv();
            if (iv != null) output.write(iv.getIV());
        }

        return new CipherOutputStream(output, cipher.getCipher());
    }
}
