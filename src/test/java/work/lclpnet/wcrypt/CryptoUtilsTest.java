package work.lclpnet.wcrypt;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilsTest {

    @Test
    void randomBytes() {
        assertNotNull(CryptoUtils.randomBytes(5));
        assertThrows(IllegalArgumentException.class, () -> CryptoUtils.randomBytes(-1));
    }

    @Test
    void generateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = CryptoUtils.randomBytes(8);

        SecretKey key1 = CryptoUtils.generateKey("test123", salt, "AES");
        SecretKey key2 = CryptoUtils.generateKey(new char[] {'t', 'e', 's', 't', '1', '2', '3'}, salt, "AES");

        assertEquals(key1, key2);
    }

    @Test
    void getAvailableCiphers() {
        Set<String> available = CryptoUtils.getAvailableCiphers();
        assertNotNull(available);
        assertInstanceOf(Set.class, available);
    }
}