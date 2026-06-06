package com.coldentry.specter;

enum SpecterModelProvider {
	OPENAI_COMPATIBLE("OpenAI-compatible"),
	OLLAMA_NATIVE("Ollama native");

	private final String displayName;

	SpecterModelProvider(String displayName) {
		this.displayName = displayName;
	}

	static SpecterModelProvider fromPreference(String value,
			SpecterModelProvider fallback) {
		if (value == null || value.isBlank()) {
			return fallback;
		}
		try {
			return valueOf(value.trim());
		}
		catch (IllegalArgumentException e) {
			return fallback;
		}
	}

	@Override
	public String toString() {
		return displayName;
	}
}
