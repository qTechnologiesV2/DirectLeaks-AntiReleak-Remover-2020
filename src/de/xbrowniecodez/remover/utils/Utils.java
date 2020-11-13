package de.xbrowniecodez.remover.utils;

import java.io.InputStream;
import java.util.zip.ZipOutputStream;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;

public class Utils {
	public static InsnList copyInsnList(InsnList original) {
		InsnList newInsnList = new InsnList();

		for (AbstractInsnNode insn = original.getFirst(); insn != null; insn = insn.getNext()) {
			newInsnList.add(insn);
		}

		return newInsnList;
	}
	public static void writeToFile(ZipOutputStream outputStream, InputStream inputStream) throws Throwable {
		byte[] buffer = new byte[4096];
		try {
			while (inputStream.available() > 0) {
				int data = inputStream.read(buffer);
				outputStream.write(buffer, 0, data);
			}
		} finally {
			inputStream.close();
			outputStream.closeEntry();
		}

	}
}
