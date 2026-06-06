package com.coldentry.specter;

import java.util.ArrayList;
import java.util.List;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

final class SpecterModelConfigurationManager {

	private static final String PROFILE_COUNT_KEY = "profiles.count";
	private static final String SELECTED_INDEX_KEY = "profiles.selectedIndex";
	private static final String PROFILE_PREFIX = "profiles.";
	private static final String PROVIDER_SUFFIX = ".provider";
	private static final String BASE_URL_SUFFIX = ".baseUrl";
	private static final String API_KEY_SUFFIX = ".apiKey";
	private static final String MODEL_SUFFIX = ".modelName";
	private static final String RETURN_THINKING_SUFFIX = ".returnThinking";
	private static final String REASONING_EFFORT_SUFFIX = ".reasoningEffort";

	private final Preferences preferences =
		Preferences.userNodeForPackage(SpecterModelConfigurationManager.class);
	private volatile State state = loadState();

	SpecterOpenAiConfiguration currentConfiguration() {
		return state.selectedConfiguration();
	}

	boolean hasConfiguration() {
		return state.hasSelection();
	}

	Snapshot snapshot() {
		return state.snapshot();
	}

	void reloadFromPreferences() {
		try {
			preferences.sync();
		}
		catch (BackingStoreException e) {
			throw new IllegalStateException("Unable to reload model configurations", e);
		}
		state = loadState();
	}

	void updateConfigurations(List<SpecterOpenAiConfiguration> configurations, int selectedIndex) {
		if (configurations == null || configurations.isEmpty()) {
			throw new IllegalArgumentException("At least one configuration is required");
		}
		if (selectedIndex < 0 || selectedIndex >= configurations.size()) {
			throw new IllegalArgumentException("Selected configuration index is out of range");
		}

		State nextState = new State(List.copyOf(configurations), selectedIndex);
		storeState(nextState);
		state = nextState;
	}

	private State loadState() {
		int profileCount = preferences.getInt(PROFILE_COUNT_KEY, 0);
		if (profileCount > 0) {
			List<SpecterOpenAiConfiguration> configurations = new ArrayList<>(profileCount);
			for (int i = 0; i < profileCount; i++) {
				String keyPrefix = PROFILE_PREFIX + i;
				String baseUrl = preferences.get(keyPrefix + BASE_URL_SUFFIX, null);
				SpecterModelProvider provider = SpecterModelProvider.fromPreference(
					preferences.get(keyPrefix + PROVIDER_SUFFIX, null),
					inferProvider(baseUrl));
				configurations.add(SpecterOpenAiConfiguration.of(
					provider,
					baseUrl,
					preferences.get(keyPrefix + API_KEY_SUFFIX, null),
					preferences.get(keyPrefix + MODEL_SUFFIX, null),
					readNullableBoolean(keyPrefix + RETURN_THINKING_SUFFIX),
					preferences.get(keyPrefix + REASONING_EFFORT_SUFFIX, null)));
			}

			if (!configurations.isEmpty()) {
				int selectedIndex = preferences.getInt(SELECTED_INDEX_KEY, 0);
				int boundedIndex = Math.max(0, Math.min(selectedIndex, configurations.size() - 1));
				return new State(List.copyOf(configurations), boundedIndex);
			}
		}
		return new State(List.of(), -1);
	}

	private void storeState(State nextState) {
		int existingCount = preferences.getInt(PROFILE_COUNT_KEY, 0);
		for (int i = 0; i < Math.max(existingCount, nextState.configurations().size()); i++) {
			String keyPrefix = PROFILE_PREFIX + i;
			if (i >= nextState.configurations().size()) {
				preferences.remove(keyPrefix + PROVIDER_SUFFIX);
				preferences.remove(keyPrefix + BASE_URL_SUFFIX);
				preferences.remove(keyPrefix + API_KEY_SUFFIX);
				preferences.remove(keyPrefix + MODEL_SUFFIX);
				preferences.remove(keyPrefix + RETURN_THINKING_SUFFIX);
				preferences.remove(keyPrefix + REASONING_EFFORT_SUFFIX);
				continue;
			}

			SpecterOpenAiConfiguration configuration = nextState.configurations().get(i);
			preferences.put(keyPrefix + PROVIDER_SUFFIX, configuration.provider().name());
			putNullable(keyPrefix + BASE_URL_SUFFIX, configuration.baseUrl());
			putNullable(keyPrefix + API_KEY_SUFFIX, configuration.apiKey());
			putNullable(keyPrefix + MODEL_SUFFIX, configuration.modelName());
			putNullableBoolean(keyPrefix + RETURN_THINKING_SUFFIX, configuration.returnThinking());
			putNullable(keyPrefix + REASONING_EFFORT_SUFFIX, configuration.reasoningEffort());
		}

		preferences.putInt(PROFILE_COUNT_KEY, nextState.configurations().size());
		preferences.putInt(SELECTED_INDEX_KEY, nextState.selectedIndex());
		try {
			preferences.flush();
		}
		catch (BackingStoreException e) {
			throw new IllegalStateException("Unable to persist model configurations", e);
		}
	}

	private SpecterModelProvider inferProvider(String baseUrl) {
		if (SpecterOpenAiConfiguration.of(baseUrl, null, null, null, null)
				.usesNativeOllamaApi()) {
			return SpecterModelProvider.OLLAMA_NATIVE;
		}
		return SpecterModelProvider.OPENAI_COMPATIBLE;
	}

	private void putNullable(String key, String value) {
		if (value == null) {
			preferences.remove(key);
			return;
		}
		preferences.put(key, value);
	}

	private Boolean readNullableBoolean(String key) {
		String value = preferences.get(key, null);
		if (value == null) {
			return null;
		}
		return Boolean.valueOf(value);
	}

	private void putNullableBoolean(String key, Boolean value) {
		if (value == null) {
			preferences.remove(key);
			return;
		}
		preferences.put(key, value.toString());
	}

	record Snapshot(List<SpecterOpenAiConfiguration> configurations, int selectedIndex) {
		Snapshot {
			configurations = List.copyOf(configurations);
		}
	}

	private record State(List<SpecterOpenAiConfiguration> configurations, int selectedIndex) {
		private State {
			configurations = List.copyOf(configurations);
		}

		private SpecterOpenAiConfiguration selectedConfiguration() {
			if (!hasSelection()) {
				return null;
			}
			return configurations.get(selectedIndex);
		}

		private Snapshot snapshot() {
			return new Snapshot(configurations, selectedIndex);
		}

		private boolean hasSelection() {
			return selectedIndex >= 0 && selectedIndex < configurations.size();
		}
	}
}
