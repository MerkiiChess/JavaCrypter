package ru.merkii.crypt.agent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Map;

/**
 * Attach with -javaagent:opcode-agent.jar[=some/package/prefix/] and every class
 * whose internal name starts with that prefix gets its substituted opcodes
 * restored to the real ones before the JVM's own verifier ever looks at the
 * bytes. With no prefix given, every application class gets checked (platform/
 * bootstrap classes are skipped regardless - see the null loader check below).
 *
 * This is what actually plays the role of "the custom JVM" from JarProtector's
 * README: a jar produced by `protect` only runs with this agent attached, but
 * unlike a real patched JVM it's a few hundred lines of plain Java running on
 * a completely stock JDK.
 */
public final class OpcodeRestoringAgent {

    public static void premain(String agentArgs, Instrumentation instrumentation) {
        String prefix = (agentArgs == null || agentArgs.isBlank()) ? "" : agentArgs;
        Map<Integer, Integer> substituteToOriginal = ReverseOpcodeMap.build();

        instrumentation.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                     ProtectionDomain protectionDomain, byte[] classfileBuffer) {
                if (loader == null || className == null || !className.startsWith(prefix)) {
                    return null; // null = "no change", the JVM proceeds with the original bytes
                }
                return RawClassFile.restoreOpcodes(classfileBuffer, substituteToOriginal);
            }
        });
    }

    private OpcodeRestoringAgent() {
    }
}
