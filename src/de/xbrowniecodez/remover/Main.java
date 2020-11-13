package de.xbrowniecodez.remover;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import de.xbrowniecodez.remover.utils.Utils;

public class Main {
    public static String prefix = "[InjectorRemover] ";

    public static void main(String[] args) throws Throwable {
        System.out.println(prefix + "Remover for DirectLeaks AntiReleak System by xBrownieCodez");
        if (args.length < 0) {
            System.out.println(prefix + "Please specify an input file");
            return;
        }
        if (!args[0].endsWith(".jar")) {
            System.out.println(prefix + "Input file must be a .jar");
            return;
        }
        System.out.println(prefix + "Processing...");
        process(args[0]);
    }

    public static void process(String input) throws Throwable {
        ZipFile zipFile = new ZipFile(input);
        File outputFile = new File(input.replace(".jar", "") + "-Output.jar");
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        ZipOutputStream out = new ZipOutputStream(new FileOutputStream(outputFile));
        try {
            while (entries.hasMoreElements()) {
                ZipEntry entry = (ZipEntry) entries.nextElement();
                if (!entry.isDirectory() && entry.getName().endsWith(".class")
                        && !entry.getName().equals("module-info.class")) {
                    try (InputStream in = zipFile.getInputStream(entry)) {
                        ClassReader cr = new ClassReader(in);
                        ClassNode classNode = new ClassNode();
                        cr.accept(classNode, 0);
                        Processor exe = new Processor();
                        exe.process(classNode);
                        ClassWriter cw = new ClassWriter(0);
                        classNode.accept(cw);
                        ZipEntry newEntry = new ZipEntry(entry.getName());
                        out.putNextEntry(newEntry);
                        if (!entry.getName().contains("directleaks")) {
                            Utils.writeToFile(out, new ByteArrayInputStream(cw.toByteArray()));
                        }
                        in.close();
                    }
                } else {
                    entry.setTime(System.currentTimeMillis());
                    out.putNextEntry(entry);
                    Utils.writeToFile(out, zipFile.getInputStream(entry));
                }

            }

        } finally {
            zipFile.close();
            out.close();

        }
        System.out.println(prefix + "Done! Output: " + outputFile);

    }

}
