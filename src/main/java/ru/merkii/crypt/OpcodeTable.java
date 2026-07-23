package ru.merkii.crypt;

import java.util.List;

/**
 * The single source of truth for the opcode substitution mapping. JarProtector
 * reads this forward (real opcode -> substitute) when protecting a jar, and the
 * runtime agent reads it backward (substitute -> real opcode) when restoring a
 * jar's bytecode before the JVM ever sees it. Keeping both sides pointed at the
 * same table is the whole point of this class - they can't drift apart.
 *
 * Raw opcode values are used instead of org.objectweb.asm.Opcodes constants so
 * that ru.merkii.crypt.agent (which has no ASM dependency, deliberately, since
 * it ships as its own tiny jar) can depend on this class too.
 */
public final class OpcodeTable {

    public record Entry(String mnemonic, int originalOpcode, int substituteOpcode) {
    }

    public static List<Entry> entries() {
        return List.of(
                new Entry("return", 177, 247),
                new Entry("areturn", 176, 248),
                new Entry("aconst_null", 1, 246),
                new Entry("pop", 87, 245),
                new Entry("invokevirtual", 182, 243),
                new Entry("dup", 89, 242),
                new Entry("bipush", 16, 241),
                new Entry("invokespecial", 183, 244)
        );
    }

    private OpcodeTable() {
    }
}
