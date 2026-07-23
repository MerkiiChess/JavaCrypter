package ru.merkii.crypt;

import org.objectweb.asm.tree.ClassNode;

/**
 * Pairs a parsed class with a write-order priority. protectJar writes classes out
 * in priority order instead of whatever order they happened to appear in the
 * source jar, so a cracked diff against the original jar doesn't line up entry
 * for entry. Deeper subclasses get a higher priority (see JarProtector.rankByInheritanceDepth).
 */
final class ClassPair implements Comparable<ClassPair> {

    final ClassNode classNode;
    final int priority;

    ClassPair(ClassNode classNode, int priority) {
        this.classNode = classNode;
        this.priority = priority;
    }

    @Override
    public int compareTo(ClassPair other) {
        return other.priority - this.priority;
    }
}
