package ru.merkii.crypt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Regression test for two bugs that used to make protectJar unusable:
 * writing straight to AbstractInsnNode.opcode didn't compile (it's package-private
 * in ASM), and even with that patched, ClassWriter's COMPUTE_MAXS blew up with an
 * ArrayIndexOutOfBoundsException the moment it saw one of our substituted opcodes.
 *
 * The output class is deliberately something a stock ASM/ClassReader can no longer
 * parse - that's the whole point of the scheme - so this checks the raw bytes
 * instead of reading the protected class back in.
 */
class JarProtectorTest {

    @Test
    void protectRewritesReturnOpcodeAndProducesALoadableJar(@TempDir Path tempDir) throws Exception {
        File inputJar = tempDir.resolve("sample.jar").toFile();
        writeFixtureJar(inputJar);

        new JarProtector(inputJar).run();

        File outputJar = tempDir.resolve("sample_crypted.jar").toFile();
        try (JarFile jar = new JarFile(outputJar)) {
            byte[] classBytes = jar.getInputStream(jar.getEntry("ru/merkii/crypt/testfixture/Sample.class")).readAllBytes();

            // both RETURN instructions (0xB1 / 177) should be gone, replaced by the
            // substitute opcode (0xF7 / 247); nothing else in this tiny fixture happens
            // to contain either byte value
            assertEquals(0, countOccurrences(classBytes, (byte) 177), "no plain return opcode should remain");
            assertEquals(2, countOccurrences(classBytes, (byte) 247), "both returns should have been substituted");

            assertNotNull(jar.getEntry("ru/merkii/crypt/crypt/StringDecryptor.class"));
            assertNotNull(jar.getEntry("ru/merkii/crypt/crypt/key.bin"));
        }
    }

    private static int countOccurrences(byte[] data, byte value) {
        int count = 0;
        for (byte b : data) {
            if (b == value) {
                count++;
            }
        }
        return count;
    }

    private static void writeFixtureJar(File jarFile) throws Exception {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "ru/merkii/crypt/testfixture/Sample", null, "java/lang/Object", null);
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        MethodVisitor doNothing = cw.visitMethod(Opcodes.ACC_PUBLIC, "doNothing", "()V", null, null);
        doNothing.visitCode();
        doNothing.visitInsn(Opcodes.RETURN);
        doNothing.visitMaxs(0, 0);
        doNothing.visitEnd();
        cw.visitEnd();

        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jarFile))) {
            out.putNextEntry(new JarEntry("ru/merkii/crypt/testfixture/Sample.class"));
            out.write(cw.toByteArray());
        }
    }
}
