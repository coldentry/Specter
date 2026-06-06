package com.coldentry.specter;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.internal.Json;
import ghidra.program.model.listing.Program;

final class SpecterLlmPromptInvoker implements SpecterPromptInvoker {

	private static final String DSL_TOOL_NAME = "RunSpecterDslQuery";
	private static final String PROMPT_FUNCTION = "prompt";
	private static final String UPDATE_KEYWORD = "UPDATE";
	private static final Pattern UPDATE_STATEMENT_PATTERN = Pattern.compile(
		"(?is)(^|;|\\bDO\\s+)\\s*UPDATE\\b");
	private static final Pattern PROMPT_CALL_PATTERN = Pattern.compile(
		"(?is)\\b" + PROMPT_FUNCTION + "\\s*\\(");
	private static final String PROMPT_DSL_TOOL_DESCRIPTION =
		"Run a read-only Specter DSL query against the active program. Use this inside " +
			"DSL prompt() for program context. Valid tables are only FUNCTION, STRING, DATA, " +
			"REFERENCE, and SYMBOL. instructions(entry), decompilation(entry), callgraph_level(entry), " +
			"and concat(...) are SELECT expressions, not tables. Database-writing UPDATE statements and nested prompt() " +
			"calls are not available from DSL prompt().";
	private static final Set<String> READ_ONLY_TOOL_NAMES = Set.of(
		DSL_TOOL_NAME,
		"GetCurrentAddress",
		"SearchDataTypesByNameRegex",
		"GetDataTypeDetails",
		"ListSubAgents",
		"GetSubAgentDetails");

	private final SpecterModelConfigurationManager configurationManager;
	private final SpecterToolHost toolHost;
	private final SpecterToolHost readOnlyToolHost;

	SpecterLlmPromptInvoker(SpecterModelConfigurationManager configurationManager,
			SpecterToolHost toolHost) {
		this.configurationManager = configurationManager;
		this.toolHost = toolHost;
		readOnlyToolHost = new ReadOnlyToolHost(toolHost);
	}

	@Override
	public String invoke(String prompt, SpecterStreamingResponseListener listener) {
		SpecterStreamingResponseListener progressListener =
			Objects.requireNonNullElse(listener, SpecterStreamingResponseListener.IGNORE);
		SpecterOpenAiConfiguration configuration = configurationManager.currentConfiguration();
		if (configuration == null) {
			throw new IllegalStateException("No model configured. Run /model to configure one.");
		}

		String systemPrompt = SpecterSystemPrompt.build(toolHost.currentProgram());
		SpecterChatService chatService =
			SpecterChatServices.create(configuration, readOnlyToolHost, systemPrompt);

		AtomicReference<SpecterAssistantReply> replyRef = new AtomicReference<>();
		AtomicReference<Throwable> errorRef = new AtomicReference<>();
		SpecterStreamingRequest request = chatService.streamReply(List.of(SpecterChatMessage.user(prompt)),
			new SpecterStreamingResponseListener() {
				@Override
				public void onPartialResponse(String partialResponse) {
					// DSL prompt() returns the final response in the result table.
				}

				@Override
				public void onPartialThinking(String partialThinking) {
					progressListener.onPartialThinking(partialThinking);
				}

				@Override
				public void onToolCall(String toolName, String arguments) {
					progressListener.onToolCall(toolName, arguments);
				}

				@Override
				public void onToolResult(String toolName, String result) {
					progressListener.onToolResult(toolName, result);
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
		if (reply == null) {
			return "";
		}
		return reply.text().trim();
	}

	private static final class ReadOnlyToolHost implements SpecterToolHost {

		private final SpecterToolHost delegate;
		private final List<ToolSpecification> toolSpecifications;

		private ReadOnlyToolHost(SpecterToolHost delegate) {
			this.delegate = delegate;
			toolSpecifications = delegate.toolSpecifications().stream()
					.filter(specification -> READ_ONLY_TOOL_NAMES.contains(specification.name()))
					.map(ReadOnlyToolHost::toPromptToolSpecification)
					.toList();
		}

		@Override
		public Program currentProgram() {
			return delegate.currentProgram();
		}

		@Override
		public List<ToolSpecification> toolSpecifications() {
			return toolSpecifications;
		}

		@Override
		public String execute(ToolExecutionRequest request) {
			if (!READ_ONLY_TOOL_NAMES.contains(request.name())) {
				return "Error: Tool '" + request.name() + "' is not available from DSL prompt().";
			}
			if (DSL_TOOL_NAME.equals(request.name())) {
				String validationError = validateDslQuery(request);
				if (validationError != null) {
					return validationError;
				}
			}
			return delegate.execute(request);
		}

		private static ToolSpecification toPromptToolSpecification(ToolSpecification specification) {
			if (!DSL_TOOL_NAME.equals(specification.name())) {
				return specification;
			}
			return specification.toBuilder()
					.description(PROMPT_DSL_TOOL_DESCRIPTION)
					.build();
		}

		private static String validateDslQuery(ToolExecutionRequest request) {
			String query;
			try {
				query = readQueryArgument(request);
			}
			catch (RuntimeException e) {
				return "Error: " + e.getMessage();
			}
			if (containsUpdateStatement(query)) {
				return "Error: RunSpecterDslQuery is read-only from DSL prompt(); UPDATE is not available.";
			}
			if (containsPromptCall(query)) {
				return "Error: Nested prompt() calls are not available from DSL prompt().";
			}
			return null;
		}

		private static String readQueryArgument(ToolExecutionRequest request) {
			Object parsed = Json.fromJson(request.arguments(), Map.class);
			if (!(parsed instanceof Map<?, ?> arguments)) {
				throw new IllegalArgumentException("Tool arguments must be a JSON object.");
			}
			Object value = arguments.get("query");
			if (value instanceof String query && !query.isBlank()) {
				return query.strip();
			}
			throw new IllegalArgumentException(
				"Tool 'RunSpecterDslQuery' requires a non-empty string argument named 'query'.");
		}

		private static boolean startsWithKeyword(String text, String keyword) {
			String stripped = text.stripLeading();
			return stripped.equalsIgnoreCase(keyword) ||
				stripped.regionMatches(true, 0, keyword + " ", 0, keyword.length() + 1);
		}

		private static boolean containsUpdateStatement(String query) {
			return startsWithKeyword(query, UPDATE_KEYWORD) ||
				UPDATE_STATEMENT_PATTERN.matcher(query).find();
		}

		private static boolean containsPromptCall(String query) {
			return PROMPT_CALL_PATTERN.matcher(query).find();
		}
	}
}
