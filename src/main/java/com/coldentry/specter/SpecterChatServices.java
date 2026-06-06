package com.coldentry.specter;

final class SpecterChatServices {

	private SpecterChatServices() {
		// Utility class.
	}

	static SpecterChatService create(SpecterModelConfigurationManager configurationManager,
			SpecterToolHost toolHost) {
		return new ConfigurableSpecterChatService(configurationManager, toolHost);
	}

	static SpecterChatService create(SpecterOpenAiConfiguration configuration,
			SpecterToolHost toolHost, String systemPrompt) {
		if (configuration.provider() == SpecterModelProvider.OLLAMA_NATIVE) {
			return new OllamaStreamingChatService(configuration, toolHost, systemPrompt);
		}
		return new LangChain4jOpenAiStreamingChatService(configuration, toolHost, systemPrompt);
	}
}
