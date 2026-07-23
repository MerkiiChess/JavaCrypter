package ru.merkii.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

final class IoUtil {

    private IoUtil() {
    }

    static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
    }
}
