package work.lclpnet.wcrypt.cipher;

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

public class SimpleCipherImpl implements SimpleCipher {

    public static final IllegalStateException NOT_INITIALIZED = new IllegalStateException("Cipher not initialized");

    public final String algorithm;
    protected final SecretKey key;
    @Nullable
    protected Cipher cipher;

    public SimpleCipherImpl(String algorithm, SecretKey key) {
        this.algorithm = algorithm;
        this.key = key;
    }

    @Override
    @Nullable
    public final Cipher getCipher() {
        return cipher;
    }

    @Override
    public void begin(Mode mode) throws GeneralSecurityException {
        cipher = Cipher.getInstance(algorithm);
        cipher.init(mode.opmode, key);
    }

    @Override
    public final byte[] update(byte[] input, int offset, int length) {
        if (cipher == null) throw NOT_INITIALIZED;

        return cipher.update(input, offset, length);
    }

    @Override
    public final byte[] doFinal() throws IllegalBlockSizeException, BadPaddingException {
        if (cipher == null) throw NOT_INITIALIZED;

        return cipher.doFinal();
    }

    @Override
    public final byte[] doFinal(byte[] input, int offset, int length) throws IllegalBlockSizeException,
            BadPaddingException {

        if (cipher == null) throw NOT_INITIALIZED;

        return cipher.doFinal(input, offset, length);
    }
}
