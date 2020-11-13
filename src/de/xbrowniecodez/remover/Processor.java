package de.xbrowniecodez.remover;

import org.objectweb.asm.Handle;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import de.xbrowniecodez.remover.utils.Utils;

public class Processor {
	public void process(ClassNode classNode) throws Throwable {
		invokeDynamicTransfomer(classNode);
		stringEncryptionTransformer(classNode);
		signatureRemover(classNode);

	}
	private void invokeDynamicTransfomer(ClassNode classNode) {
		String bootstrapDesc = "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;";
		for (MethodNode methodNode : classNode.methods) {
			InsnList copy = Utils.copyInsnList(methodNode.instructions);
			for (int i = 0; i < copy.size(); i++) {
				AbstractInsnNode insn = copy.get(i);
				if (insn instanceof InvokeDynamicInsnNode) {
					InvokeDynamicInsnNode dyn = (InvokeDynamicInsnNode) insn;
					if (dyn.bsmArgs.length == 9) {
						Handle bootstrap = dyn.bsm;
                        if (bootstrap.getDesc().equals(bootstrapDesc)) {
							int legitOpCode = (Integer) dyn.bsmArgs[0];			
							String legitOwner = dyn.bsmArgs[1].toString().replace("L", "").replace(";", "");
							String legitMethod = decryptInvoke(dyn.bsmArgs[2].toString(),2038);
							String legitDesc = decryptInvoke(dyn.bsmArgs[3].toString(),1928);
							MethodInsnNode replacement;
							if (legitOpCode == 1) { // INVOKEVIRTUAL							   
								replacement = new MethodInsnNode(182, legitOwner, legitMethod,
										legitDesc, false);
								methodNode.instructions.set(insn, replacement);
							} else if (legitOpCode == 0) { // INVOKESTATIC
                                replacement = new MethodInsnNode(184, legitOwner, legitMethod,
                                        legitDesc, false);
                                methodNode.instructions.set(insn, replacement);
							}
						}
					}
				}
			}
		}
	}

	private void stringEncryptionTransformer(ClassNode classNode) {
		if (classNode.superName.equals("org/bukkit/plugin/java/JavaPlugin")
				|| classNode.superName.equals("net/md_5/bungee/api/plugin/Plugin")) {
			for (MethodNode methodNode : classNode.methods) {
				InsnList nodes = methodNode.instructions;
				for (int i = 0; i < nodes.size(); i++) {
					AbstractInsnNode instruction = nodes.get(i);
					if (instruction instanceof LdcInsnNode) {
						if (instruction.getNext() instanceof MethodInsnNode) {
							LdcInsnNode ldc = (LdcInsnNode) instruction;
							MethodInsnNode methodinsnnode = (MethodInsnNode) ldc.getNext();
							if (ldc.cst instanceof String) {
								if (methodinsnnode.name.equalsIgnoreCase("\u0003") && methodinsnnode.desc
										.equalsIgnoreCase("(Ljava/lang/String;)Ljava/lang/String;")) {
									methodNode.instructions.remove(methodinsnnode);
									ldc.cst = decryptionArray((String) ldc.cst);
								}
							}
						}
					}
				}
			}
		}
	}
	   private static String decryptionArray(String message) {
	        try {
	            char[] messageChars = message.toCharArray();
	            char[] newMessage = new char[messageChars.length];
	            char[] XORKEY = new char[] { '\u4832', '\u2385', '\u2386', '\u9813', '\u9125', '\u4582', '\u0913', '\u3422',
	                    '\u0853', '\u0724' };
	            char[] XORKEY2 = new char[] { '\u4820', '\u8403', '\u8753', '\u3802', '\u3840', '\u3894', '\u8739',
	                    '\u1038', '\u8304', '\u3333' };
	            for (int j = 0; j < messageChars.length; ++j) {
	                newMessage[j] = (char) (messageChars[j] ^ XORKEY[j % XORKEY.length]);
	            }
	            char[] decryptedmsg = new char[newMessage.length];
	            for (int j = 0; j < messageChars.length; ++j) {
	                decryptedmsg[j] = (char) (newMessage[j] ^ XORKEY2[j % XORKEY2.length]);
	            }
	            return new String(decryptedmsg);
	        } catch (Exception ignore) {
	            return message;
	        }
	    }

	private void signatureRemover(ClassNode classNode) {
		if (classNode.superName.equals("org/bukkit/plugin/java/JavaPlugin")
				|| classNode.superName.equals("net/md_5/bungee/api/plugin/Plugin")) {
			classNode.signature = null;
		}
	}
	
    public static String decryptInvoke(String msg, int key) {
        char[] encClassNameChars = msg.toCharArray();
        char[] classNameChars = new char[encClassNameChars.length];
        for (int i = 0; i < encClassNameChars.length; ++i) {
            classNameChars[i] = (char)(encClassNameChars[i] ^ key);
        }
        return new String(classNameChars);
    }

}
