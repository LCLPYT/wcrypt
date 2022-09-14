package work.lclpnet.wcrypt;

import org.junit.jupiter.api.Test;
import work.lclpnet.wcrypt.aes.AESCrypto;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptoManagerTest {

    @Test
    void test() throws GeneralSecurityException, IOException {
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

        assertEquals("Hello World.", new String(bytes, StandardCharsets.UTF_8));
    }
}