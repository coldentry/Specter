package com.coldentry.specter;

import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

final class SpecterDatabaseEditPreferences {

	private static final String ALWAYS_ALLOW_PREFIX = "databaseEdit.alwaysAllow.";

	private final Preferences preferences =
		Preferences.userNodeForPackage(SpecterDatabaseEditPreferences.class);

	boolean alwaysAllow(String toolName) {
		return preferences.getBoolean(ALWAYS_ALLOW_PREFIX + toolName, false);
	}

	void setAlwaysAllow(String toolName, boolean allowed) {
		preferences.putBoolean(ALWAYS_ALLOW_PREFIX + toolName, allowed);
		try {
			preferences.flush();
		}
		catch (BackingStoreException e) {
			throw new IllegalStateException("Unable to persist database edit approval preferences", e);
		}
	}
}
