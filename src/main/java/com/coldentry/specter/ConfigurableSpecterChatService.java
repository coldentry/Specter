package com.coldentry.specter;

import java.util.List;

final class ConfigurableSpecterChatService implements SpecterChatService {

	private final SpecterModelConfigurationManager configurationManager;
	private final SpecterToolHost toolHost;

	ConfigurableSpecterChatService(SpecterModelConfigurationManager configurationManager,
			SpecterToolHost toolHost) {
		this.configurationManager = configurationManager;
		this.toolHost = toolHost;
	}

	@Override
	public SpecterStreamingRequest streamReply(List<SpecterChatMessage> conversation,
			SpecterStreamingResponseListener listener) {
		SpecterOpenAiConfiguration configuration = configurationManager.currentConfiguration();
		if (configuration == null) {
			throw new IllegalStateException("No model configured. Run /model to configure one.");
		}
		return createChatService(configuration).streamReply(conversation, listener);
	}

	private SpecterChatService createChatService(SpecterOpenAiConfiguration configuration) {
		return SpecterChatServices.create(configuration, toolHost,
			SpecterSystemPrompt.build(toolHost.currentProgram()));
	}
}
