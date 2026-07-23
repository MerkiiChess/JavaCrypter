package ru.merkii.crypt.agent;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * A hand-rolled class-file reader, because ASM's ClassReader refuses to touch
 * anything containing our substituted opcodes - it throws while decoding the
 * very first Code attribute it meets one in (confirmed by JarProtectorTest).
 *
 * We don't need to understand what the bytecode *means*, only where each
 * instruction starts, so this walks the class file structure just enough to
 * find every method's Code attribute and then walks its instructions using
 * the JVM spec's per-opcode length table. Since substitution never changes an
 * instruction's length, patching is a single in-place byte swap - nothing
 * else in the class file ever needs to shift or be resized.
 */
final class RawClassFile {

    private static final long MAGIC = 0xCAFEBABEL;

    private final byte[] data;
    private int pos;
    private int codeArrayStart;

    private RawClassFile(byte[] data) {
        this.data = data;
    }

    /**
     * Returns a patched copy of classBytes with every substituted opcode swapped
     * back to the real one, or null if classBytes doesn't parse as a class file
     * we understand - callers should treat null as "leave it alone".
     */
    static byte[] restoreOpcodes(byte[] classBytes, Map<Integer, Integer> substituteToOriginal) {
        byte[] patched = classBytes.clone();
        RawClassFile reader = new RawClassFile(patched);
        try {
            reader.walkAndPatch(substituteToOriginal);
        } catch (RuntimeException e) {
            return null;
        }
        return patched;
    }

    private void walkAndPatch(Map<Integer, Integer> substituteToOriginal) {
        if (u4() != MAGIC) {
            throw new IllegalArgumentException("not a class file");
        }
        u2(); // minor version
        u2(); // major version

        Map<Integer, String> utf8ByIndex = readConstantPool();

        u2(); // access_flags
        u2(); // this_class
        u2(); // super_class

        int interfaceCount = u2();
        pos += interfaceCount * 2;

        walkMembers(utf8ByIndex, substituteToOriginal, false);
        walkMembers(utf8ByIndex, substituteToOriginal, true);

        int classAttributeCount = u2();
        for (int i = 0; i < classAttributeCount; i++) {
            skipAttribute();
        }
    }

    /** Walks the constant pool, capturing UTF8 entries' text so attribute names can be resolved later on. */
    private Map<Integer, String> readConstantPool() {
        int count = u2();
        Map<Integer, String> utf8ByIndex = new HashMap<>();
        for (int index = 1; index < count; index++) {
            int tag = u1();
            switch (tag) {
                case 1 -> { // Utf8
                    int length = u2();
                    utf8ByIndex.put(index, new String(data, pos, length, StandardCharsets.UTF_8));
                    pos += length;
                }
                case 7, 8, 16, 19, 20 -> pos += 2; // Class, String, MethodType, Module, Package
                case 15 -> pos += 3;               // MethodHandle
                case 3, 4, 9, 10, 11, 12, 17, 18 -> pos += 4; // Integer, Float, Fieldref, Methodref,
                                                               // InterfaceMethodref, NameAndType, Dynamic, InvokeDynamic
                case 5, 6 -> {                      // Long, Double - each occupies two constant pool slots
                    pos += 8;
                    index++;
                }
                default -> throw new IllegalArgumentException("unknown constant pool tag " + tag);
            }
        }
        return utf8ByIndex;
    }

    private void walkMembers(Map<Integer, String> utf8ByIndex, Map<Integer, Integer> substituteToOriginal, boolean isMethods) {
        int count = u2();
        for (int i = 0; i < count; i++) {
            u2(); // access_flags
            u2(); // name_index
            u2(); // descriptor_index
            int attributeCount = u2();
            for (int a = 0; a < attributeCount; a++) {
                if (isMethods && "Code".equals(utf8ByIndex.get(peekAttributeNameIndex()))) {
                    patchCodeAttribute(substituteToOriginal);
                } else {
                    skipAttribute();
                }
            }
        }
    }

    private int peekAttributeNameIndex() {
        return ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
    }

    private void skipAttribute() {
        u2(); // attribute_name_index
        long length = u4();
        pos += length;
    }

    private void patchCodeAttribute(Map<Integer, Integer> substituteToOriginal) {
        u2(); // attribute_name_index
        u4(); // attribute_length - redundant with the fields below, no need to trust it
        u2(); // max_stack
        u2(); // max_locals
        int codeLength = (int) u4();
        int codeStart = pos;
        this.codeArrayStart = codeStart;
        walkInstructions(codeStart, codeStart + codeLength, substituteToOriginal);
        pos = codeStart + codeLength;

        int exceptionTableLength = u2();
        pos += exceptionTableLength * 8; // start_pc, end_pc, handler_pc, catch_type: 4 x u2

        int nestedAttributeCount = u2();
        for (int i = 0; i < nestedAttributeCount; i++) {
            skipAttribute();
        }
    }

    private void walkInstructions(int start, int end, Map<Integer, Integer> substituteToOriginal) {
        int bci = start;
        while (bci < end) {
            int opcode = data[bci] & 0xFF;
            Integer original = substituteToOriginal.get(opcode);
            if (original != null) {
                data[bci] = original.byteValue();
                opcode = original; // length/operand shape is identical - only the byte value changed
            }
            bci += instructionLength(opcode, bci);
        }
    }

    /** Length in bytes (including the opcode byte itself) of the instruction starting at bci. */
    private int instructionLength(int opcode, int bci) {
        return switch (opcode) {
            case 16 -> 2;                    // bipush
            case 17 -> 3;                    // sipush
            case 18 -> 2;                    // ldc
            case 19, 20 -> 3;                // ldc_w, ldc2_w
            case 21, 22, 23, 24, 25 -> 2;    // iload, lload, fload, dload, aload
            case 54, 55, 56, 57, 58 -> 2;    // istore, lstore, fstore, dstore, astore
            case 132 -> 3;                   // iinc
            case 153, 154, 155, 156, 157, 158,
                 159, 160, 161, 162, 163, 164,
                 165, 166, 167, 168 -> 3;     // if*, if_icmp*, if_acmp*, goto, jsr
            case 169 -> 2;                   // ret
            case 170 -> tableswitchLength(bci);
            case 171 -> lookupswitchLength(bci);
            case 178, 179, 180, 181 -> 3;    // getstatic, putstatic, getfield, putfield
            case 182, 183, 184 -> 3;         // invokevirtual, invokespecial, invokestatic
            case 185, 186 -> 5;              // invokeinterface, invokedynamic
            case 187 -> 3;                   // new
            case 188 -> 2;                   // newarray
            case 189 -> 3;                   // anewarray
            case 192, 193 -> 3;              // checkcast, instanceof
            case 196 -> wideLength(bci);
            case 197 -> 4;                   // multianewarray
            case 198, 199 -> 3;              // ifnull, ifnonnull
            case 200, 201 -> 5;              // goto_w, jsr_w
            default -> 1;                    // every other standard opcode is a single byte, no operand
        };
    }

    private int tableswitchLength(int opcodeBci) {
        int afterOpcode = opcodeBci + 1;
        int padding = (4 - ((afterOpcode - codeArrayStart) % 4)) % 4;
        int tableStart = afterOpcode + padding;
        int low = readIntAt(tableStart + 4);
        int high = readIntAt(tableStart + 8);
        int entryCount = high - low + 1;
        return 1 + padding + 12 + entryCount * 4;
    }

    private int lookupswitchLength(int opcodeBci) {
        int afterOpcode = opcodeBci + 1;
        int padding = (4 - ((afterOpcode - codeArrayStart) % 4)) % 4;
        int tableStart = afterOpcode + padding;
        int pairCount = readIntAt(tableStart + 4);
        return 1 + padding + 8 + pairCount * 8;
    }

    private int wideLength(int opcodeBci) {
        int modifiedOpcode = data[opcodeBci + 1] & 0xFF;
        return modifiedOpcode == 132 /* iinc */ ? 6 : 4;
    }

    private int readIntAt(int offset) {
        return ((data[offset] & 0xFF) << 24) | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
    }

    private int u1() {
        return data[pos++] & 0xFF;
    }

    private int u2() {
        int value = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2;
        return value;
    }

    private long u4() {
        long value = ((long) (data[pos] & 0xFF) << 24) | ((data[pos + 1] & 0xFF) << 16)
                | ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);
        pos += 4;
        return value;
    }
}
