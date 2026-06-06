package com.coldentry.specter;

import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

final class SpecterDisplayPreferences {

	private static final String SHOW_THINKING_KEY = "display.showThinking";

	private final Preferences preferences =
		Preferences.userNodeForPackage(SpecterDisplayPreferences.class);

	boolean showThinking() {
		return preferences.getBoolean(SHOW_THINKING_KEY, false);
	}

	void setShowThinking(boolean showThinking) {
		preferences.putBoolean(SHOW_THINKING_KEY, showThinking);
		try {
			preferences.flush();
		}
		catch (BackingStoreException e) {
			throw new IllegalStateException("Unable to persist display preferences", e);
		}
	}
}
