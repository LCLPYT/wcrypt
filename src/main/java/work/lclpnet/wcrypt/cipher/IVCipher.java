package work.lclpnet.wcrypt.cipher;

import javax.annotation.Nullable;
import javax.crypto.spec.IvParameterSpec;

public interface IVCipher extends SimpleCipher {

    @Nullable
    IvParameterSpec getIv();

    void setIv(@Nullable IvParameterSpec iv);
}
