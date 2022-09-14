package work.lclpnet.wcrypt.cipher;

import javax.crypto.SecretKey;

public interface CipherProvider {

    SimpleCipher provide(SecretKey key);
}
