package work.lclpnet.wcrypt.cipher;

import work.lclpnet.wcrypt.CryptoUtils;

import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;

public class IvCipherImpl extends SimpleCipherImpl implements IVCipher {

    @Nullable
    private IvParameterSpec iv;

    public IvCipherImpl(String algorithm, SecretKey key) {
        this(algorithm, key, null);
    }

    public IvCipherImpl(String algorithm, SecretKey key, @Nullable IvParameterSpec iv) {
        super(algorithm, key);
        this.iv = iv;
    }

    @Override
    @Nullable
    public IvParameterSpec getIv() {
        return iv;
    }

    @Override
    public void begin(Mode mode) throws GeneralSecurityException {
        if (iv == null) iv = CryptoUtils.generateIv();
        cipher = Cipher.getInstance(algorithm);
        cipher.init(mode.opmode, key, iv);
    }
}
