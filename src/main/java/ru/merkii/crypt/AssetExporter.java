package ru.merkii.crypt;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * Pulls everything that isn't a .class file out of a jar - configs, lang files,
 * textures, whatever - into a separate jar. Useful when you want to ship assets
 * without dragging the protected bytecode along with them.
 */
final class AssetExporter {

    private final File inputFile;

    AssetExporter(File inputFile) {
        this.inputFile = inputFile;
    }

    void run() throws Exception {
        File outputFile = new File(inputFile.getPath().replace(".jar", "_assetsExported.jar"));
        System.out.println("Exporting assets from " + inputFile.getName() + " to " + outputFile.getName());

        try (JarFile inputJar = new JarFile(inputFile);
             JarOutputStream out = new JarOutputStream(new FileOutputStream(outputFile))) {

            Enumeration<JarEntry> entries = inputJar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    continue;
                }
                try (InputStream in = inputJar.getInputStream(entry)) {
                    out.putNextEntry(new JarEntry(entry.getName()));
                    IoUtil.copy(in, out);
                }
            }
        }
    }
}
