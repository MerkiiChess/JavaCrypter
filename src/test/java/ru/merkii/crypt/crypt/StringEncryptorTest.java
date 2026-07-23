package ru.merkii.crypt.crypt;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class StringEncryptorTest {

    @Test
    void encryptedStringDecryptsBackToTheOriginal() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);

        StringEncryptor encryptor = new StringEncryptor(key);
        String cipherText = encryptor.encrypt("hello from a licensed build");

        String plainText = StringDecryptor.decrypt(cipherText, new javax.crypto.spec.SecretKeySpec(key, "AES"));

        assertEquals("hello from a licensed build", plainText);
    }

    @Test
    void sameInputEncryptsDifferentlyEachTime() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        StringEncryptor encryptor = new StringEncryptor(key);

        String first = encryptor.encrypt("same string");
        String second = encryptor.encrypt("same string");

        // random nonce per call means ciphertext should never repeat, even for identical input
        assertNotEquals(first, second);
    }
}
