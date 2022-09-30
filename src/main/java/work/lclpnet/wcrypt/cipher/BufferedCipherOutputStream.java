package work.lclpnet.wcrypt.cipher;

import javax.annotation.Nonnull;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class BufferedCipherOutputStream extends FilterOutputStream {

    protected final Cipher cipher;
    protected final byte[] buf;
    protected int count = 0;
    private byte[] outBuffer;

    /**
     * Creates an output stream filter built on top of the specified
     * underlying output stream.
     *
     * @param out the underlying output stream to be assigned to
     *            the field <tt>this.out</tt> for later use, or
     *            <code>null</code> if this instance is to be
     *            created without an underlying stream.
     * @param cipher The cipher to use for encryption. Must be initialized passing data through the stream.
     */
    public BufferedCipherOutputStream(OutputStream out, Cipher cipher) {
        this(out, cipher, 1024);
    }

    /**
     * Creates an output stream filter built on top of the specified
     * underlying output stream.
     *
     * @param out the underlying output stream to be assigned to
     *            the field <tt>this.out</tt> for later use, or
     *            <code>null</code> if this instance is to be
     *            created without an underlying stream.
     * @param cipher The cipher to use for encryption. Must be initialized passing data through the stream.
     * @param bufferSize The size of the internal buffer.
     */
    public BufferedCipherOutputStream(OutputStream out, Cipher cipher, int bufferSize) {
        super(out);
        this.cipher = cipher;
        this.buf = new byte[bufferSize];
    }

    private void flushBuffer() throws IOException {
        if (count <= 0) return;

        outBuffer = cipher.update(buf, 0, count);
        count = 0;
        out.write(outBuffer);
    }

    @Override
    public synchronized void write(int b) throws IOException {
        if (count >= buf.length) flushBuffer();
        buf[count++] = (byte) b;
    }

    @Override
    public void write(@Nonnull byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public synchronized void write(@Nonnull byte[] b, int off, int len) throws IOException {
        if ((off | len | (b.length - (len + off)) | (off + len)) < 0)
            throw new IndexOutOfBoundsException();

        int written = off;

        while (written - off < len) {
            if (count >= buf.length) flushBuffer();

            // amount = either remaining space in current buffer or remaining bytes, if there is enough space
            int amount = Math.min(this.buf.length - this.count, len - written + off);
            System.arraycopy(b, written, this.buf, this.count, amount);
            count += amount;
            written += amount;
        }
    }

    @Override
    public void close() throws IOException {
        try (OutputStream _out = out) {
            outBuffer = cipher.doFinal(buf, 0, count);
            _out.write(outBuffer);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IOException("Could not complete encryption", e);
        }
    }
}
