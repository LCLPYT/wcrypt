package work.lclpnet.wcrypt.cipher;

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

public interface SimpleCipher {

    @Nullable
    Cipher getCipher();

    void begin(Mode mode) throws GeneralSecurityException;

    default byte[] update(byte[] input) {
        return update(input, 0, input.length);
    }

    byte[] update(byte[] input, int offset, int length);

    byte[] doFinal() throws IllegalBlockSizeException, BadPaddingException;

    default byte[] doFinal(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
        return doFinal(input, 0, input.length);
    }

    byte[] doFinal(byte[] input, int offset, int length) throws IllegalBlockSizeException, BadPaddingException;

    /**
     * Reads all bytes from the input, updates the cipher and writes the result to the output.
     *
     * @param in The input.
     * @param out The output.
     */
    default void transfer(InputStream in, OutputStream out)
            throws IOException, IllegalBlockSizeException, BadPaddingException {
        transfer(in, out, 64);
    }

    /**
     * Reads all bytes from the input, updates the cipher and writes the result to the output.
     *
     * @param in The input.
     * @param out The output.
     * @param bufferSize The size of the chunks to update the buffer with.
     */
    default void transfer(InputStream in, OutputStream out, int bufferSize)
            throws IOException, IllegalBlockSizeException, BadPaddingException {

        byte[] buffer = new byte[bufferSize];
        int read;

        while ((read = in.read(buffer)) != -1) {
            byte[] chunk = update(buffer, 0, read);
            if (chunk != null)
                out.write(chunk);
        }

        byte[] end = doFinal();
        if (end != null)
            out.write(end);
    }

    enum Mode {
        ENCRYPT(Cipher.ENCRYPT_MODE),
        DECRYPT(Cipher.DECRYPT_MODE);

        public final int opmode;

        Mode(int opmode) {
            this.opmode = opmode;
        }
    }
}
