package com.coldentry.specter;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.ChatMessage;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.ToolExecutionResultMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.http.client.sse.ServerSentEvent;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ToolChoice;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.openai.OpenAiChatRequestParameters;
import dev.langchain4j.model.openai.OpenAiChatResponseMetadata;
import dev.langchain4j.model.openai.OpenAiStreamingResponseBuilder;
import dev.langchain4j.model.openai.internal.OpenAiClient;
import dev.langchain4j.model.openai.internal.OpenAiUtils;
import dev.langchain4j.model.openai.internal.ParsedAndRawResponse;
import dev.langchain4j.model.openai.internal.ResponseHandle;
import dev.langchain4j.model.openai.internal.chat.ChatCompletionChoice;
import dev.langchain4j.model.openai.internal.chat.ChatCompletionRequest;
import dev.langchain4j.model.openai.internal.chat.ChatCompletionResponse;
import dev.langchain4j.model.openai.internal.chat.Delta;
import dev.langchain4j.model.openai.internal.shared.StreamOptions;
import dev.langchain4j.model.output.TokenUsage;

final class LangChain4jOpenAiStreamingChatService implements SpecterChatService {

	private static final Pattern JSON_STRING_FIELD_PATTERN = Pattern.compile(
		"\"(?:reasoning_content|thinking)\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");

	private final SpecterOpenAiConfiguration configuration;
	private final SpecterToolHost toolHost;
	private final String systemPrompt;
	private volatile OpenAiClient client;

	LangChain4jOpenAiStreamingChatService(SpecterOpenAiConfiguration configuration,
			SpecterToolHost toolHost, String systemPrompt) {
		this.configuration = configuration;
		this.toolHost = toolHost;
		this.systemPrompt = systemPrompt;
	}

	@Override
	public SpecterStreamingRequest streamReply(List<SpecterChatMessage> conversation,
			SpecterStreamingResponseListener listener) {
		AtomicBoolean canceled = new AtomicBoolean();
		AtomicReference<ResponseHandle> responseHandleRef = new AtomicReference<>();
		AtomicReference<Thread> workerThreadRef = new AtomicReference<>();
		return new SpecterStreamingRequest() {
			@Override
			public void run() {
				if (canceled.get()) {
					return;
				}

				workerThreadRef.set(Thread.currentThread());
				try {
					listener.onComplete(executeConversation(toLangChainMessages(conversation), listener,
						canceled, responseHandleRef));
				}
				catch (CancellationException e) {
					// Request was canceled locally.
				}
				catch (Throwable error) {
					if (!canceled.get()) {
						listener.onError(error);
					}
				}
				finally {
					responseHandleRef.set(null);
					workerThreadRef.set(null);
				}
			}

			@Override
			public void cancel() {
				canceled.set(true);
				ResponseHandle responseHandle = responseHandleRef.getAndSet(null);
				if (responseHandle != null) {
					responseHandle.cancel();
				}
				Thread workerThread = workerThreadRef.get();
				if (workerThread != null) {
					workerThread.interrupt();
				}
			}
		};
	}

	private OpenAiClient getOrCreateClient() {
		OpenAiClient currentClient = client;
		if (currentClient != null) {
			return currentClient;
		}

		synchronized (this) {
			if (client == null) {
				client = OpenAiClient.builder()
						.baseUrl(configuration.baseUrl())
						.apiKey(configuration.apiKey())
						.connectTimeout(Duration.ofSeconds(15))
						.readTimeout(Duration.ofMinutes(5))
						.build();
			}
			return client;
		}
	}

	private List<ChatMessage> toLangChainMessages(List<SpecterChatMessage> conversation) {
		return conversation.stream()
				.map(this::toLangChainMessage)
				.toList();
	}

	private SpecterAssistantReply executeConversation(List<ChatMessage> conversation,
			SpecterStreamingResponseListener listener, AtomicBoolean canceled,
			AtomicReference<ResponseHandle> responseHandleRef) {
		List<ChatMessage> messages = new ArrayList<>();
		messages.add(SystemMessage.from(systemPrompt));
		messages.addAll(conversation);
		StringBuilder completeThinking = new StringBuilder();
		SpecterTokenUsage aggregateTokenUsage = null;

		while (true) {
			throwIfCanceled(canceled);
			ModelTurn turn = executeModelTurn(messages, listener, canceled, responseHandleRef);
			if (!turn.thinking().isEmpty()) {
				completeThinking.append(turn.thinking());
			}
			aggregateTokenUsage = SpecterTokenUsage.sum(aggregateTokenUsage, turn.tokenUsage());

			AiMessage aiMessage = turn.response().aiMessage();
			if (aiMessage == null) {
				return new SpecterAssistantReply("", completeThinking.toString(), aggregateTokenUsage);
			}
			if (aiMessage.hasToolExecutionRequests()) {
				messages.add(aiMessage);
				throwIfCanceled(canceled);
				addToolResults(messages, aiMessage.toolExecutionRequests(), listener);
				continue;
			}
			return new SpecterAssistantReply(turn.text(), completeThinking.toString(),
				aggregateTokenUsage);
		}
	}

	private ModelTurn executeModelTurn(List<ChatMessage> messages,
			SpecterStreamingResponseListener listener, AtomicBoolean canceled,
			AtomicReference<ResponseHandle> responseHandleRef) {
		CountDownLatch completionLatch = new CountDownLatch(1);
		AtomicReference<Throwable> errorRef = new AtomicReference<>();
		OpenAiStreamingResponseBuilder responseBuilder =
			new OpenAiStreamingResponseBuilder(Boolean.TRUE.equals(configuration.returnThinking()));
		StringBuilder partialResponse = new StringBuilder();
		StringBuilder partialThinking = new StringBuilder();
		OpenAiChatRequestParameters requestParameters = buildRequestParameters();

		ChatRequest request = ChatRequest.builder()
				.messages(messages)
				.parameters(requestParameters)
				.build();

		ChatCompletionRequest streamingRequest = OpenAiUtils.toOpenAiChatRequest(request,
			requestParameters, false, false)
				.stream(Boolean.TRUE)
				.streamOptions(StreamOptions.builder()
						.includeUsage(Boolean.TRUE)
						.build())
				.build();

		ResponseHandle responseHandle = getOrCreateClient().chatCompletion(streamingRequest)
				.onRawPartialResponse(rawResponse -> {
					if (canceled.get()) {
						ResponseHandle activeHandle = responseHandleRef.get();
						if (activeHandle != null) {
							activeHandle.cancel();
						}
						return;
					}

					responseBuilder.append(rawResponse);

					String responseText = partialResponse(rawResponse);
					if (!responseText.isEmpty()) {
						partialResponse.append(responseText);
						listener.onPartialResponse(responseText);
					}

					String thinkingText = partialThinking(rawResponse);
					if (!thinkingText.isEmpty()) {
						partialThinking.append(thinkingText);
						listener.onPartialThinking(thinkingText);
					}
				})
				.onComplete(completionLatch::countDown)
				.onError(error -> {
					errorRef.set(error);
					completionLatch.countDown();
				})
				.execute();
		responseHandleRef.set(responseHandle);
		if (canceled.get()) {
			responseHandle.cancel();
		}

		awaitCompletion(completionLatch, canceled);
		responseHandleRef.compareAndSet(responseHandle, null);
		throwIfCanceled(canceled);

		Throwable error = errorRef.get();
		if (error != null) {
			throw new IllegalStateException(error.getMessage(), error);
		}

		ChatResponse response = responseBuilder.build();
		String responseText = emptyIfNull(partialResponse.toString());
		String thinkingText = emptyIfNull(partialThinking.toString());
		if (response.aiMessage() != null) {
			if (responseText.isEmpty()) {
				responseText = emptyIfNull(response.aiMessage().text());
			}
			if (thinkingText.isEmpty()) {
				thinkingText = emptyIfNull(response.aiMessage().thinking());
			}
		}
		if (thinkingText.isEmpty()) {
			thinkingText = extractThinkingFromMetadata(response);
		}
		return new ModelTurn(response, responseText, thinkingText,
			toSpecterTokenUsage(response.tokenUsage()));
	}

	private OpenAiChatRequestParameters buildRequestParameters() {
		OpenAiChatRequestParameters.Builder builder = OpenAiChatRequestParameters.builder()
				.modelName(configuration.modelName())
				.toolSpecifications(toolHost.toolSpecifications())
				.toolChoice(ToolChoice.AUTO);
		String reasoningEffort = resolveReasoningEffort(configuration);
		if (reasoningEffort != null) {
			builder.reasoningEffort(reasoningEffort);
			builder.customParameters(Map.of("reasoning", Map.of("effort", reasoningEffort)));
		}
		return builder.build();
	}

	private SpecterTokenUsage toSpecterTokenUsage(TokenUsage tokenUsage) {
		if (tokenUsage == null) {
			return null;
		}
		return SpecterTokenUsage.of(tokenUsage.inputTokenCount(), tokenUsage.outputTokenCount(),
			tokenUsage.totalTokenCount());
	}

	private void addToolResults(List<ChatMessage> messages,
			List<ToolExecutionRequest> toolExecutionRequests,
			SpecterStreamingResponseListener listener) {
		for (ToolExecutionRequest request : toolExecutionRequests) {
			listener.onToolCall(request.name(), request.arguments());
			String result = toolHost.execute(request);
			listener.onToolResult(request.name(), result);
			messages.add(ToolExecutionResultMessage.from(request, result));
		}
	}

	private void awaitCompletion(CountDownLatch completionLatch, AtomicBoolean canceled) {
		try {
			completionLatch.await();
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			if (canceled.get()) {
				throw new CancellationException("Request canceled");
			}
			throw new IllegalStateException("Request interrupted", e);
		}
		if (canceled.get()) {
			throw new CancellationException("Request canceled");
		}
	}

	private ChatMessage toLangChainMessage(SpecterChatMessage message) {
		return switch (message.role()) {
			case USER -> UserMessage.from(message.text());
			case ASSISTANT -> toAssistantMessage(message);
		};
	}

	private AiMessage toAssistantMessage(SpecterChatMessage message) {
		if (!message.hasThinking()) {
			return AiMessage.from(message.text());
		}
		return AiMessage.builder()
				.text(message.text())
				.thinking(message.thinking())
				.build();
	}

	private static String emptyIfNull(String value) {
		return value == null ? "" : value;
	}

	private static String extractThinkingFromMetadata(ChatResponse response) {
		if (!(response.metadata() instanceof OpenAiChatResponseMetadata metadata)) {
			return "";
		}

		StringBuilder thinking = new StringBuilder();
		for (ServerSentEvent event : metadata.rawServerSentEvents()) {
			if (event == null) {
				continue;
			}

			String data = event.data();
			if (data == null || data.isEmpty() || "[DONE]".equals(data)) {
				continue;
			}

			Matcher matcher = JSON_STRING_FIELD_PATTERN.matcher(data);
			while (matcher.find()) {
				thinking.append(unescapeJsonString(matcher.group(1)));
			}
		}
		return thinking.toString();
	}

	private static String unescapeJsonString(String value) {
		StringBuilder result = new StringBuilder(value.length());
		boolean escaping = false;
		for (int i = 0; i < value.length(); i++) {
			char current = value.charAt(i);
			if (!escaping) {
				if (current == '\\') {
					escaping = true;
				}
				else {
					result.append(current);
				}
				continue;
			}

			switch (current) {
				case '"', '\\', '/' -> result.append(current);
				case 'b' -> result.append('\b');
				case 'f' -> result.append('\f');
				case 'n' -> result.append('\n');
				case 'r' -> result.append('\r');
				case 't' -> result.append('\t');
				case 'u' -> {
					if (i + 4 < value.length()) {
						String hex = value.substring(i + 1, i + 5);
						try {
							result.append((char) Integer.parseInt(hex, 16));
							i += 4;
						}
						catch (NumberFormatException e) {
							result.append("\\u").append(hex);
							i += 4;
						}
					}
					else {
						result.append("\\u");
					}
				}
				default -> result.append(current);
			}
			escaping = false;
		}
		if (escaping) {
			result.append('\\');
		}
		return result.toString();
	}

	private static String resolveReasoningEffort(SpecterOpenAiConfiguration configuration) {
		if (configuration.reasoningEffort() != null) {
			return configuration.reasoningEffort();
		}
		return null;
	}

	private static String partialResponse(ParsedAndRawResponse<ChatCompletionResponse> rawResponse) {
		Delta delta = delta(rawResponse);
		return delta == null ? "" : emptyIfNull(delta.content());
	}

	private static String partialThinking(ParsedAndRawResponse<ChatCompletionResponse> rawResponse) {
		Delta delta = delta(rawResponse);
		return delta == null ? "" : emptyIfNull(delta.reasoningContent());
	}

	private static Delta delta(ParsedAndRawResponse<ChatCompletionResponse> rawResponse) {
		if (rawResponse == null || rawResponse.parsedResponse() == null) {
			return null;
		}
		List<ChatCompletionChoice> choices = rawResponse.parsedResponse().choices();
		if (choices == null || choices.isEmpty()) {
			return null;
		}
		ChatCompletionChoice choice = choices.get(0);
		return choice == null ? null : choice.delta();
	}

	private static void throwIfCanceled(AtomicBoolean canceled) {
		if (canceled.get()) {
			throw new CancellationException("Request canceled");
		}
	}

	private record ModelTurn(ChatResponse response, String text, String thinking,
			SpecterTokenUsage tokenUsage) {
	}
}
