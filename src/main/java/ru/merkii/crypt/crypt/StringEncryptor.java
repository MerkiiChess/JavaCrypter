package ru.merkii.crypt.crypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Build-time counterpart to StringDecryptor. Generates one AES key per protect
 * run and encrypts every string constant JarProtector pulls out of the bytecode
 * with it. The key travels with the jar (see JarProtector.embedStringDecryptor),
 * which is the usual tradeoff for a client-side protection scheme - it raises
 * the bar for casual extraction, it's not meant to stop someone with a debugger
 * attached to your custom JVM.
 */
public final class StringEncryptor {

    private static final int GCM_TAG_BITS = 128;
    private static final int NONCE_LENGTH = 12;

    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();
    private final EncryptionStats stats = new EncryptionStats();

    public StringEncryptor() {
        this(generateKey());
    }

    StringEncryptor(byte[] rawKey) {
        this.key = new SecretKeySpec(rawKey, "AES");
    }

    public String encrypt(String plainText) {
        try {
            byte[] nonce = new byte[NONCE_LENGTH];
            random.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] payload = new byte[NONCE_LENGTH + cipherText.length];
            System.arraycopy(nonce, 0, payload, 0, NONCE_LENGTH);
            System.arraycopy(cipherText, 0, payload, NONCE_LENGTH, cipherText.length);

            stats.record(payload.length);
            return Base64.getEncoder().encodeToString(payload);
        } catch (Exception e) {
            throw new IllegalStateException("failed to encrypt a string constant", e);
        }
    }

    public byte[] keyBytes() {
        return key.getEncoded();
    }

    public EncryptionStats stats() {
        return stats;
    }

    private static byte[] generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            return keyGenerator.generateKey().getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("this JVM has no AES support", e);
        }
    }
}
