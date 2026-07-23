package ru.merkii.crypt;

import java.io.File;

public final class Main {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            return;
        }

        File jarFile = new File(args[1]);
        if (!jarFile.isFile()) {
            System.err.println("No such jar: " + jarFile.getPath());
            return;
        }

        switch (args[0]) {
            case "protect" -> new JarProtector(jarFile).run();
            case "export-assets" -> new AssetExporter(jarFile).run();
            default -> printUsage();
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  protect <input.jar>        obfuscate bytecode and encrypt string constants");
        System.out.println("  export-assets <input.jar>  copy everything that isn't a .class file into its own jar");
    }

    private Main() {
    }
}
