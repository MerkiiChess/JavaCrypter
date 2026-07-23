package ru.merkii.crypt.crypt;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * This class gets copied byte-for-byte into every jar that goes through
 * JarProtector, and calls to decrypt(String) get spliced in wherever a plain
 * string literal used to be. It reads its AES key from key.bin, which
 * JarProtector drops right next to this class file at protect time - see
 * JarProtector.embedStringDecryptor.
 */
public final class StringDecryptor {

    private static final int GCM_TAG_BITS = 128;
    private static final int NONCE_LENGTH = 12;

    // loaded lazily, on first real use - just referencing this class (e.g. from a
    // test) shouldn't blow up looking for a key.bin that only exists once this
    // class has actually been embedded into a protected jar
    private static volatile SecretKeySpec embeddedKey;

    private StringDecryptor() {
    }

    public static String decrypt(String base64CipherText) {
        return decrypt(base64CipherText, embeddedKey());
    }

    private static SecretKeySpec embeddedKey() {
        SecretKeySpec key = embeddedKey;
        if (key == null) {
            key = loadEmbeddedKey();
            embeddedKey = key;
        }
        return key;
    }

    static String decrypt(String base64CipherText, SecretKeySpec key) {
        try {
            byte[] payload = Base64.getDecoder().decode(base64CipherText);
            byte[] nonce = new byte[NONCE_LENGTH];
            System.arraycopy(payload, 0, nonce, 0, NONCE_LENGTH);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] plainBytes = cipher.doFinal(payload, NONCE_LENGTH, payload.length - NONCE_LENGTH);
            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // if this blows up the jar was tampered with or the key is missing - either way
            // there's nothing sane left to return, so fail loudly instead of limping on
            throw new IllegalStateException("could not decrypt a protected string", e);
        }
    }

    private static SecretKeySpec loadEmbeddedKey() {
        try (InputStream in = StringDecryptor.class.getResourceAsStream("key.bin")) {
            if (in == null) {
                throw new IllegalStateException("key.bin is missing next to StringDecryptor.class");
            }
            return new SecretKeySpec(in.readAllBytes(), "AES");
        } catch (IOException e) {
            throw new IllegalStateException("could not read the embedded AES key", e);
        }
    }
}
