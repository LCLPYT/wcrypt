package work.lclpnet.wcrypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class TestHelper {

    public static InputStream getJarResource(String resource) {
        return TestHelper.class.getResourceAsStream(resource);
    }

    public static byte[] getAllBytes(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] buffer = new byte[1024];
        int read;

        while ((read = in.read(buffer)) != -1)
            out.write(buffer, 0, read);

        return out.toByteArray();
    }

    public static byte[] readSalt() throws IOException {
        try (InputStream in = getJarResource("/content.enc.salt")) {
            return getAllBytes(in);
        }
    }
}
