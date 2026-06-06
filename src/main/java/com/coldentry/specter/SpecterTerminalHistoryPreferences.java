package com.coldentry.specter;

import java.util.ArrayList;
import java.util.List;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

final class SpecterTerminalHistoryPreferences {

	private static final int MAX_HISTORY_ENTRIES = 100;
	private static final int MAX_CHUNK_LENGTH = 4_000;
	private static final String HISTORY_PREFIX = "terminalHistory.";
	private static final String COUNT_SUFFIX = ".count";
	private static final String ENTRY_PREFIX = ".entry.";
	private static final String CHUNK_COUNT_SUFFIX = ".chunkCount";
	private static final String CHUNK_PREFIX = ".chunk.";

	private final Preferences preferences =
		Preferences.userNodeForPackage(SpecterTerminalHistoryPreferences.class);

	List<String> loadHistory(String modeName) {
		try {
			preferences.sync();
		}
		catch (BackingStoreException e) {
			throw new IllegalStateException("Unable to reload terminal history", e);
		}

		String prefix = HISTORY_PREFIX + modeName;
		int count = preferences.getInt(prefix + COUNT_SUFFIX, 0);
		List<String> history = new ArrayList<>(Math.min(count, MAX_HISTORY_ENTRIES));
		for (int i = 0; i < count && history.size() < MAX_HISTORY_ENTRIES; i++) {
			String entry = readEntry(prefix, i);
			if (entry != null && !entry.isBlank()) {
				history.add(entry);
			}
		}
		return List.copyOf(history);
	}

	void saveHistory(String modeName, List<String> history) {
		String prefix = HISTORY_PREFIX + modeName;
		int existingCount = preferences.getInt(prefix + COUNT_SUFFIX, 0);
		for (int i = 0; i < existingCount; i++) {
			removeEntry(prefix, i);
		}

		List<String> entries = lastEntries(history);
		for (int i = 0; i < entries.size(); i++) {
			writeEntry(prefix, i, entries.get(i));
		}
		preferences.putInt(prefix + COUNT_SUFFIX, entries.size());
		try {
			preferences.flush();
		}
		catch (BackingStoreException e) {
			throw new IllegalStateException("Unable to persist terminal history", e);
		}
	}

	private String readEntry(String prefix, int index) {
		String entryPrefix = prefix + ENTRY_PREFIX + index;
		int chunkCount = preferences.getInt(entryPrefix + CHUNK_COUNT_SUFFIX, 0);
		if (chunkCount <= 0) {
			return null;
		}
		StringBuilder builder = new StringBuilder();
		for (int chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
			String chunk = preferences.get(entryPrefix + CHUNK_PREFIX + chunkIndex, null);
			if (chunk == null) {
				return null;
			}
			builder.append(chunk);
		}
		return builder.toString();
	}

	private void writeEntry(String prefix, int index, String entry) {
		String entryPrefix = prefix + ENTRY_PREFIX + index;
		int chunkCount = Math.max(1, (entry.length() + MAX_CHUNK_LENGTH - 1) / MAX_CHUNK_LENGTH);
		preferences.putInt(entryPrefix + CHUNK_COUNT_SUFFIX, chunkCount);
		for (int chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
			int start = chunkIndex * MAX_CHUNK_LENGTH;
			int end = Math.min(entry.length(), start + MAX_CHUNK_LENGTH);
			preferences.put(entryPrefix + CHUNK_PREFIX + chunkIndex, entry.substring(start, end));
		}
	}

	private void removeEntry(String prefix, int index) {
		String entryPrefix = prefix + ENTRY_PREFIX + index;
		int chunkCount = preferences.getInt(entryPrefix + CHUNK_COUNT_SUFFIX, 0);
		for (int chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
			preferences.remove(entryPrefix + CHUNK_PREFIX + chunkIndex);
		}
		preferences.remove(entryPrefix + CHUNK_COUNT_SUFFIX);
	}

	private static List<String> lastEntries(List<String> history) {
		if (history.size() <= MAX_HISTORY_ENTRIES) {
			return List.copyOf(history);
		}
		return List.copyOf(history.subList(history.size() - MAX_HISTORY_ENTRIES, history.size()));
	}
}
