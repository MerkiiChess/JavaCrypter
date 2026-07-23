package ru.merkii.crypt.crypt;

import java.util.ArrayList;
import java.util.List;

/**
 * Keeps track of every string constant StringEncryptor touches during a protect
 * run, just so JarProtector can print a short summary at the end.
 */
public final class EncryptionStats {

    private final List<Integer> encryptedLengths = new ArrayList<>();

    public void record(int cipherTextBytes) {
        encryptedLengths.add(cipherTextBytes);
    }

    public int count() {
        return encryptedLengths.size();
    }

    public int totalBytes() {
        int sum = 0;
        for (int length : encryptedLengths) {
            sum += length;
        }
        return sum;
    }
}
