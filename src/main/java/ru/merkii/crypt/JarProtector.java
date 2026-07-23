package ru.merkii.crypt;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import ru.merkii.crypt.crypt.StringEncryptor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * Takes a plain jar and produces a "protected" copy that only makes sense to our
 * own custom JVM: a handful of opcodes get swapped for values that don't mean
 * anything to a stock JVM, and string constants get replaced with an AES-encrypted
 * blob plus a call into the StringDecryptor we embed in the output jar.
 */
final class JarProtector {

    private static final String DECRYPTOR_PACKAGE = "ru/merkii/crypt/crypt/";
    private static final String DECRYPTOR_CLASS = DECRYPTOR_PACKAGE + "StringDecryptor";

    private final File inputFile;
    private final List<ClassNode> classes = new ArrayList<>();

    JarProtector(File inputFile) {
        this.inputFile = inputFile;
    }

    void run() throws IOException {
        File outputFile = new File(inputFile.getPath().replace(".jar", "_crypted.jar"));
        System.out.println("Protecting " + inputFile.getName());

        List<OpcodeSubstitution> opcodeTable = buildOpcodeTable();
        StringEncryptor stringEncryptor = new StringEncryptor();

        try (JarFile inputJar = new JarFile(inputFile);
             JarOutputStream out = new JarOutputStream(new FileOutputStream(outputFile))) {

            copyResourcesAndCollectClasses(inputJar, out);

            substituteOpcodes(opcodeTable);
            encryptStringConstants(stringEncryptor);

            for (ClassPair pair : rankByInheritanceDepth()) {
                writeClass(out, pair.classNode);
            }
            embedStringDecryptor(out, stringEncryptor.keyBytes());
        }

        printSummary(opcodeTable, stringEncryptor);
        System.out.println("Wrote " + outputFile.getName());
    }

    /** Splits the jar: non-class entries go straight to the output, class entries get parsed for later. */
    private void copyResourcesAndCollectClasses(JarFile inputJar, JarOutputStream out) throws IOException {
        Enumeration<JarEntry> entries = inputJar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            try (InputStream in = inputJar.getInputStream(entry)) {
                if (entry.getName().endsWith(".class")) {
                    ClassReader reader = new ClassReader(in);
                    ClassNode classNode = new ClassNode();
                    reader.accept(classNode, 0);
                    classes.add(classNode);
                } else {
                    out.putNextEntry(new JarEntry(entry.getName()));
                    IoUtil.copy(in, out);
                }
            }
        }
    }

    private void substituteOpcodes(List<OpcodeSubstitution> table) {
        for (ClassNode classNode : classes) {
            for (MethodNode method : classNode.methods) {
                for (AbstractInsnNode insn : method.instructions.toArray()) {
                    for (OpcodeSubstitution substitution : table) {
                        if (insn.getOpcode() != substitution.originalOpcode()) {
                            continue;
                        }
                        AbstractInsnNode replacement = withOpcode(insn, substitution.substituteOpcode());
                        if (replacement == null) {
                            // same mnemonic but a node shape we didn't expect - leave it alone rather than guess
                            continue;
                        }
                        method.instructions.set(insn, replacement);
                        substitution.markApplied();
                    }
                }
            }
        }
    }

    /**
     * AbstractInsnNode.opcode is package-private in ASM, so we can't just flip it in
     * place - we rebuild the same kind of node with the new opcode and swap it into
     * the instruction list instead.
     */
    private static AbstractInsnNode withOpcode(AbstractInsnNode insn, int newOpcode) {
        if (insn instanceof MethodInsnNode m) {
            return new MethodInsnNode(newOpcode, m.owner, m.name, m.desc, m.itf);
        }
        if (insn instanceof IntInsnNode i) {
            return new IntInsnNode(newOpcode, i.operand);
        }
        if (insn instanceof InsnNode) {
            return new InsnNode(newOpcode);
        }
        return null;
    }

    private void encryptStringConstants(StringEncryptor encryptor) {
        for (ClassNode classNode : classes) {
            for (MethodNode method : classNode.methods) {
                for (AbstractInsnNode insn : method.instructions.toArray()) {
                    if (!(insn instanceof LdcInsnNode ldc) || !(ldc.cst instanceof String plainText)) {
                        continue;
                    }
                    if (plainText.isEmpty()) {
                        continue;
                    }
                    ldc.cst = encryptor.encrypt(plainText);
                    method.instructions.insert(ldc, new MethodInsnNode(
                            Opcodes.INVOKESTATIC,
                            DECRYPTOR_CLASS,
                            "decrypt",
                            "(Ljava/lang/String;)Ljava/lang/String;",
                            false));
                }
            }
        }
    }

    /**
     * Orders classes by how deep they sit in the (in-jar) inheritance chain instead
     * of the order they came out of the source jar, so the layout of the protected
     * jar doesn't map 1:1 onto the original. Not a strong guarantee by itself - it's
     * one more thing an attacker has to account for on top of the opcode and string
     * substitution.
     */
    private List<ClassPair> rankByInheritanceDepth() {
        Map<String, ClassNode> byInternalName = new HashMap<>();
        for (ClassNode classNode : classes) {
            byInternalName.put(classNode.name, classNode);
        }

        List<ClassPair> ranked = new ArrayList<>();
        for (ClassNode classNode : classes) {
            int depth = 0;
            String parent = classNode.superName;
            while (parent != null) {
                ClassNode parentNode = byInternalName.get(parent);
                if (parentNode == null) {
                    break; // parent isn't part of this jar (e.g. java.lang.Object)
                }
                depth++;
                parent = parentNode.superName;
            }
            ranked.add(new ClassPair(classNode, depth));
        }
        Collections.sort(ranked);
        return ranked;
    }

    private void writeClass(JarOutputStream out, ClassNode classNode) throws IOException {
        if (classNode.name.equals("module-info")) {
            return;
        }
        // no COMPUTE_MAXS/COMPUTE_FRAMES here: ASM's stack-size tables only cover the
        // standard 0-201 opcode range, and our substituted opcodes sit above that -
        // asking ASM to recompute anything for them throws ArrayIndexOutOfBoundsException.
        // The original max stack/locals are still valid since substitution never changes
        // how many values an instruction pushes or pops.
        ClassWriter writer = new ClassWriter(0);
        classNode.accept(writer);
        out.putNextEntry(new JarEntry(classNode.name + ".class"));
        out.write(writer.toByteArray());
    }

    private void embedStringDecryptor(JarOutputStream out, byte[] key) throws IOException {
        try (InputStream in = getClass().getResourceAsStream("/" + DECRYPTOR_CLASS + ".class")) {
            if (in == null) {
                throw new IllegalStateException("StringDecryptor.class is missing from our own classpath");
            }
            out.putNextEntry(new JarEntry(DECRYPTOR_CLASS + ".class"));
            IoUtil.copy(in, out);
        }
        out.putNextEntry(new JarEntry(DECRYPTOR_PACKAGE + "key.bin"));
        out.write(key);
    }

    private List<OpcodeSubstitution> buildOpcodeTable() {
        List<OpcodeSubstitution> table = new ArrayList<>();
        for (OpcodeTable.Entry entry : OpcodeTable.entries()) {
            table.add(new OpcodeSubstitution(entry.mnemonic(), entry.originalOpcode(), entry.substituteOpcode()));
        }
        return table;
    }

    private void printSummary(List<OpcodeSubstitution> table, StringEncryptor stringEncryptor) {
        System.out.println("Summary:");
        for (OpcodeSubstitution substitution : table) {
            System.out.println("  " + substitution.mnemonic() + " -> " + substitution.substituteOpcode()
                    + ": " + substitution.timesApplied());
        }
        System.out.println("Strings encrypted: " + stringEncryptor.stats().count()
                + " (" + stringEncryptor.stats().totalBytes() + " bytes)");
    }
}
