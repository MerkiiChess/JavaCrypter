package ru.merkii.crypt.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import ru.merkii.crypt.Main;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * End-to-end round trip for the agent: build a class with a lookupswitch (to
 * exercise the padding/length skip logic RawClassFile needs to walk past
 * instructions it isn't substituting) and a couple of substituted opcodes, run
 * it through the real protect pipeline, then run RawClassFile over the result
 * and actually execute the restored class - not just diff bytes - to prove the
 * agent's raw walker reconstructs something a stock JVM can run correctly.
 */
class RawClassFileTest {

    private static final String CLASS_NAME = "ru/merkii/crypt/agent/testfixture/Sample";

    @Test
    void restoredClassBehavesLikeTheOriginal(@TempDir Path tempDir) throws Exception {
        File inputJar = tempDir.resolve("sample.jar").toFile();
        writeFixtureJar(inputJar);

        Main.main(new String[]{"protect", inputJar.getPath()});

        byte[] substituted;
        try (JarFile jar = new JarFile(tempDir.resolve("sample_crypted.jar").toFile())) {
            substituted = jar.getInputStream(jar.getEntry(CLASS_NAME + ".class")).readAllBytes();
        }

        byte[] restored = RawClassFile.restoreOpcodes(substituted, ReverseOpcodeMap.build());
        assertNotNull(restored, "RawClassFile should be able to parse a protected class");

        Class<?> loaded = new ClassLoader(getClass().getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) {
                return defineClass(name, restored, 0, restored.length);
            }
        }.loadClass(CLASS_NAME.replace('/', '.'));

        Object instance = loaded.getDeclaredConstructor().newInstance();
        Method classify = loaded.getMethod("classify", int.class);
        Method voidMethod = loaded.getMethod("voidMethod");

        assertEquals(10, classify.invoke(instance, 0));
        assertEquals(20, classify.invoke(instance, 100));
        assertEquals(0, classify.invoke(instance, 7));
        voidMethod.invoke(instance); // just needs to not throw
    }

    private static void writeFixtureJar(File jarFile) throws Exception {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, CLASS_NAME, null, "java/lang/Object", null);

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        // sparse cases force ASM to emit a lookupswitch (opcode 171) rather than a tableswitch,
        // and the bipush operands below are themselves one of the substituted opcodes
        MethodVisitor classify = cw.visitMethod(Opcodes.ACC_PUBLIC, "classify", "(I)I", null, null);
        classify.visitCode();
        Label case0 = new Label();
        Label case100 = new Label();
        Label defaultCase = new Label();
        classify.visitVarInsn(Opcodes.ILOAD, 1);
        classify.visitLookupSwitchInsn(defaultCase, new int[]{0, 100}, new Label[]{case0, case100});
        classify.visitLabel(case0);
        classify.visitIntInsn(Opcodes.BIPUSH, 10);
        classify.visitInsn(Opcodes.IRETURN);
        classify.visitLabel(case100);
        classify.visitIntInsn(Opcodes.BIPUSH, 20);
        classify.visitInsn(Opcodes.IRETURN);
        classify.visitLabel(defaultCase);
        classify.visitInsn(Opcodes.ICONST_0);
        classify.visitInsn(Opcodes.IRETURN);
        classify.visitMaxs(0, 0);
        classify.visitEnd();

        MethodVisitor voidMethod = cw.visitMethod(Opcodes.ACC_PUBLIC, "voidMethod", "()V", null, null);
        voidMethod.visitCode();
        voidMethod.visitInsn(Opcodes.RETURN);
        voidMethod.visitMaxs(0, 0);
        voidMethod.visitEnd();

        cw.visitEnd();

        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jarFile))) {
            out.putNextEntry(new JarEntry(CLASS_NAME + ".class"));
            out.write(cw.toByteArray());
        }
    }
}
