package com.coldentry.specter;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

final class SpecterOpenAiConfiguration {

	static final String DEFAULT_BASE_URL = "https://api.openai.com/v1";
	static final String DEFAULT_MODEL = "gpt-4o-mini";

	private final SpecterModelProvider provider;
	private final String baseUrl;
	private final String apiKey;
	private final String modelName;
	private final Boolean returnThinking;
	private final String reasoningEffort;

	private SpecterOpenAiConfiguration(SpecterModelProvider provider, String baseUrl,
			String apiKey, String modelName, Boolean returnThinking, String reasoningEffort) {
		this.provider = provider;
		this.baseUrl = baseUrl;
		this.apiKey = apiKey;
		this.modelName = modelName;
		this.returnThinking = returnThinking;
		this.reasoningEffort = reasoningEffort;
	}

	static SpecterOpenAiConfiguration of(String baseUrl, String apiKey, String modelName,
			Boolean returnThinking, String reasoningEffort) {
		return of(SpecterModelProvider.OPENAI_COMPATIBLE, baseUrl, apiKey, modelName,
			returnThinking, reasoningEffort);
	}

	static SpecterOpenAiConfiguration of(SpecterModelProvider provider, String baseUrl,
			String apiKey, String modelName, Boolean returnThinking, String reasoningEffort) {
		return new SpecterOpenAiConfiguration(
			provider == null ? SpecterModelProvider.OPENAI_COMPATIBLE : provider,
			normalize(baseUrl),
			normalize(apiKey),
			normalizeModelName(modelName),
			returnThinking,
			normalize(reasoningEffort));
	}

	static SpecterOpenAiConfiguration defaults() {
		return of(DEFAULT_BASE_URL, "", DEFAULT_MODEL, null, null);
	}

	SpecterModelProvider provider() {
		return provider;
	}

	String baseUrl() {
		return baseUrl;
	}

	String apiKey() {
		return apiKey;
	}

	String modelName() {
		return modelName;
	}

	Boolean returnThinking() {
		return returnThinking;
	}

	String reasoningEffort() {
		return reasoningEffort;
	}

	String displayName() {
		if (baseUrl == null || baseUrl.isBlank()) {
			return modelName;
		}
		return modelName + " @ " + baseUrl;
	}

	boolean isLikelyOllama() {
		if (baseUrl == null || baseUrl.isBlank()) {
			return false;
		}
		String normalizedBaseUrl = baseUrl.toLowerCase(Locale.ROOT);
		if (normalizedBaseUrl.contains("ollama") ||
			normalizedBaseUrl.contains(":11434")) {
			return true;
		}

		try {
			URI uri = new URI(baseUrl);
			String host = uri.getHost();
			String path = uri.getPath();
			String normalizedHost = host == null ? "" : host.toLowerCase(Locale.ROOT);
			String normalizedPath = path == null ? "" : path.toLowerCase(Locale.ROOT);

			if (normalizedPath.startsWith("/api")) {
				return true;
			}
			if (isLocalHost(normalizedHost)) {
				return true;
			}
			if (normalizedPath.endsWith("/v1") &&
				!normalizedHost.equals("api.openai.com") &&
				!normalizedHost.endsWith(".openai.com")) {
				return true;
			}
		}
		catch (URISyntaxException e) {
			// Fall back to simple substring checks above for malformed values.
		}
		return false;
	}

	boolean usesNativeOllamaApi() {
		if (!isLikelyOllama()) {
			return false;
		}
		try {
			URI uri = new URI(baseUrl);
			String path = uri.getPath();
			String normalizedPath = path == null ? "" : path.toLowerCase(Locale.ROOT);
			return normalizedPath.isEmpty() ||
				normalizedPath.startsWith("/api") ||
				!normalizedPath.endsWith("/v1");
		}
		catch (URISyntaxException e) {
			String normalizedBaseUrl = baseUrl.toLowerCase(Locale.ROOT);
			return !normalizedBaseUrl.endsWith("/v1");
		}
	}

	URI ollamaApiChatUri() {
		try {
			URI uri = new URI(baseUrl);
			String path = uri.getPath();
			if (path == null || path.isEmpty()) {
				path = "";
			}
			if (path.endsWith("/")) {
				path = path.substring(0, path.length() - 1);
			}
			if (path.endsWith("/v1")) {
				path = path.substring(0, path.length() - 3);
			}
			String ollamaPath = path + "/api/chat";
			return new URI(uri.getScheme(), uri.getAuthority(), ollamaPath, null, null);
		}
		catch (URISyntaxException e) {
			throw new IllegalStateException("Invalid base URL: " + baseUrl, e);
		}
	}

	private static String normalize(String value) {
		if (value == null) {
			return null;
		}

		String trimmed = value.trim();
		return trimmed.isEmpty() ? null : trimmed;
	}

	private static String normalizeModelName(String value) {
		String normalized = normalize(value);
		return normalized == null ? DEFAULT_MODEL : normalized;
	}

	private static boolean isLocalHost(String host) {
		return "localhost".equals(host) ||
			"127.0.0.1".equals(host) ||
			"::1".equals(host) ||
			"[::1]".equals(host);
	}
}
