package ru.merkii.crypt;

/**
 * One entry in the opcode substitution table: maps a standard JVM opcode to the
 * custom value our patched JVM knows how to interpret, and keeps a running count
 * of how many times it actually got applied so we can print a summary at the end.
 */
final class OpcodeSubstitution {

    private final String mnemonic;
    private final int originalOpcode;
    private final int substituteOpcode;
    private int timesApplied;

    OpcodeSubstitution(String mnemonic, int originalOpcode, int substituteOpcode) {
        this.mnemonic = mnemonic;
        this.originalOpcode = originalOpcode;
        this.substituteOpcode = substituteOpcode;
    }

    String mnemonic() {
        return mnemonic;
    }

    int originalOpcode() {
        return originalOpcode;
    }

    int substituteOpcode() {
        return substituteOpcode;
    }

    int timesApplied() {
        return timesApplied;
    }

    void markApplied() {
        timesApplied++;
    }
}
