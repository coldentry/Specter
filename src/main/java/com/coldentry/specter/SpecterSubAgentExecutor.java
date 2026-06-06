package com.coldentry.specter;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

final class SpecterSubAgentExecutor {

	private final SpecterModelConfigurationManager configurationManager;
	private final SpecterSubAgentConfigurationManager subAgentConfigurationManager;
	private final SpecterToolHost toolHost;

	SpecterSubAgentExecutor(SpecterModelConfigurationManager configurationManager,
			SpecterSubAgentConfigurationManager subAgentConfigurationManager,
			SpecterToolHost toolHost) {
		this.configurationManager = configurationManager;
		this.subAgentConfigurationManager = subAgentConfigurationManager;
		this.toolHost = toolHost;
	}

	String invoke(String subAgentName, String task) {
		SpecterOpenAiConfiguration configuration = configurationManager.currentConfiguration();
		if (configuration == null) {
			throw new IllegalStateException("No model configured. Run /model to configure one.");
		}

		SpecterSubAgentDefinition definition =
			subAgentConfigurationManager.findByName(subAgentName);
		if (definition == null) {
			throw new IllegalStateException("Unknown sub-agent '" + subAgentName + "'.");
		}

		String systemPrompt = SpecterSystemPrompt.build(toolHost.currentProgram(),
			buildSubAgentInstructions(definition));
		SpecterChatService chatService =
			SpecterChatServices.create(configuration, toolHost, systemPrompt);

		AtomicReference<SpecterAssistantReply> replyRef = new AtomicReference<>();
		AtomicReference<Throwable> errorRef = new AtomicReference<>();
		SpecterStreamingRequest request = chatService.streamReply(List.of(SpecterChatMessage.user(task)),
			new SpecterStreamingResponseListener() {
				@Override
				public void onPartialResponse(String partialResponse) {
					// Tool result is returned after completion.
				}

				@Override
				public void onPartialThinking(String partialThinking) {
					// Do not surface sub-agent thinking in the tool result.
				}

				@Override
				public void onToolCall(String toolName, String arguments) {
					// No-op.
				}

				@Override
				public void onComplete(SpecterAssistantReply completeResponse) {
					replyRef.set(completeResponse);
				}

				@Override
				public void onError(Throwable error) {
					errorRef.set(error);
				}
			});
		request.run();

		Throwable error = errorRef.get();
		if (error != null) {
			if (error instanceof RuntimeException runtimeException) {
				throw runtimeException;
			}
			throw new IllegalStateException(error.getMessage(), error);
		}

		SpecterAssistantReply reply = replyRef.get();
		if (reply == null || reply.text().isBlank()) {
			return "Sub-agent '" + definition.name() + "' completed but returned no text output.";
		}
		return "Sub-agent: " + definition.name() + "\n\n" + reply.text().trim();
	}

	private String buildSubAgentInstructions(SpecterSubAgentDefinition definition) {
		StringBuilder builder = new StringBuilder();
		builder.append("You are acting as the sub-agent '")
				.append(definition.name())
				.append("'.\n");
		if (definition.description() != null) {
			builder.append("Sub-agent description: ")
					.append(definition.description())
					.append('\n');
		}
		builder.append("Sub-agent instructions:\n")
				.append(definition.instructions())
				.append('\n');
		builder.append(
			"Work only on the delegated task from the parent agent. Return a concise result for the parent agent to use.");
		return builder.toString();
	}
}
