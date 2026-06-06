package com.coldentry.specter;

import java.io.File;
import java.util.Locale;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

final class SpecterPreferencesInfo {

	private SpecterPreferencesInfo() {
		// Utility class.
	}

	static String nodePath() {
		return Preferences.userNodeForPackage(SpecterPreferencesInfo.class).absolutePath();
	}

	static String storageLocationDescription() {
		String userHome = System.getProperty("user.home", "~");
		String osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
		if (osName.contains("mac")) {
			return userHome + File.separator + "Library" + File.separator + "Preferences" +
				File.separator + "com.apple.java.util.prefs.plist";
		}
		if (osName.contains("win")) {
			return "HKEY_CURRENT_USER\\Software\\JavaSoft\\Prefs" + nodePath()
				.replace('/', '\\');
		}
		if (osName.contains("nux") || osName.contains("nix") || osName.contains("aix")) {
			return userHome + File.separator + ".java" + File.separator + ".userPrefs" +
				nodePath();
		}
		return "Java user preferences for node " + nodePath();
	}

	static void clearAll() {
		Preferences node = Preferences.userNodeForPackage(SpecterPreferencesInfo.class);
		try {
			clearNode(node);
			node.flush();
			node.sync();
		}
		catch (BackingStoreException e) {
			throw new IllegalStateException("Unable to clear Specter preferences", e);
		}
	}

	private static void clearNode(Preferences node) throws BackingStoreException {
		for (String childName : node.childrenNames()) {
			clearNode(node.node(childName));
		}
		node.clear();
	}
}
