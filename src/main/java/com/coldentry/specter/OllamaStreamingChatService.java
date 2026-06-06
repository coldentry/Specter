package com.coldentry.specter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.internal.Json;

final class OllamaStreamingChatService implements SpecterChatService {

	private final SpecterOpenAiConfiguration configuration;
	private final SpecterToolHost toolHost;
	private final String systemPrompt;
	private final HttpClient httpClient;

	OllamaStreamingChatService(SpecterOpenAiConfiguration configuration,
			SpecterToolHost toolHost, String systemPrompt) {
		this.configuration = configuration;
		this.toolHost = toolHost;
		this.systemPrompt = systemPrompt;
		httpClient = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(15))
				.build();
	}

	@Override
	public SpecterStreamingRequest streamReply(List<SpecterChatMessage> conversation,
			SpecterStreamingResponseListener listener) {
		AtomicBoolean canceled = new AtomicBoolean();
		AtomicReference<Thread> workerThreadRef = new AtomicReference<>();
		AtomicReference<InputStream> responseStreamRef = new AtomicReference<>();
		return new SpecterStreamingRequest() {
			@Override
			public void run() {
				if (canceled.get()) {
					return;
				}

				workerThreadRef.set(Thread.currentThread());
				try {
					listener.onComplete(
						executeConversation(conversation, listener, canceled, responseStreamRef));
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
					responseStreamRef.set(null);
					workerThreadRef.set(null);
				}
			}

			@Override
			public void cancel() {
				canceled.set(true);
				InputStream responseStream = responseStreamRef.getAndSet(null);
				if (responseStream != null) {
					try {
						responseStream.close();
					}
					catch (IOException e) {
						// Ignore close failures during cancellation.
					}
				}
				Thread workerThread = workerThreadRef.get();
				if (workerThread != null) {
					workerThread.interrupt();
				}
			}
		};
	}

	private SpecterAssistantReply executeConversation(List<SpecterChatMessage> conversation,
			SpecterStreamingResponseListener listener, AtomicBoolean canceled,
			AtomicReference<InputStream> responseStreamRef)
			throws IOException, InterruptedException {
		List<Map<String, Object>> messages = new ArrayList<>();
		messages.add(systemMessage());
		for (SpecterChatMessage message : conversation) {
			messages.add(chatMessage(message));
		}

		StringBuilder completeThinking = new StringBuilder();
		SpecterTokenUsage aggregateTokenUsage = null;
		while (true) {
			throwIfCanceled(canceled);
			OllamaTurn turn = executeTurn(messages, listener, canceled, responseStreamRef);
			if (!turn.thinking().isEmpty()) {
				completeThinking.append(turn.thinking());
			}
			aggregateTokenUsage = SpecterTokenUsage.sum(aggregateTokenUsage, turn.tokenUsage());
			messages.add(turn.assistantMessage());
			if (turn.toolCalls().isEmpty()) {
				return new SpecterAssistantReply(turn.content(), completeThinking.toString(),
					aggregateTokenUsage);
			}
			throwIfCanceled(canceled);
			addToolResults(messages, turn.toolCalls(), listener);
		}
	}

	private OllamaTurn executeTurn(List<Map<String, Object>> messages,
			SpecterStreamingResponseListener listener, AtomicBoolean canceled,
			AtomicReference<InputStream> responseStreamRef)
			throws IOException, InterruptedException {
		HttpRequest request = HttpRequest.newBuilder(configuration.ollamaApiChatUri())
				.header("Content-Type", "application/json")
				.timeout(Duration.ofMinutes(5))
				.POST(HttpRequest.BodyPublishers.ofString(buildRequestBody(messages),
					StandardCharsets.UTF_8))
				.build();

		HttpResponse<InputStream> response = httpClient.send(request,
			HttpResponse.BodyHandlers.ofInputStream());
		if (response.statusCode() < 200 || response.statusCode() >= 300) {
			throw new IllegalStateException(readFailureMessage(response));
		}

		responseStreamRef.set(response.body());
		try {
			throwIfCanceled(canceled);
			return readStreamingResponse(response.body(), listener, canceled);
		}
		finally {
			responseStreamRef.compareAndSet(response.body(), null);
		}
	}

	private String buildRequestBody(List<Map<String, Object>> messages) {
		Map<String, Object> requestBody = new LinkedHashMap<>();
		requestBody.put("model", configuration.modelName());
		requestBody.put("messages", messages);
		requestBody.put("stream", Boolean.TRUE);
		requestBody.put("tools", toOllamaTools(toolHost.toolSpecifications()));

		Object think = resolveThinkValue();
		if (think != null) {
			requestBody.put("think", think);
		}

		return Json.toJson(requestBody);
	}

	private OllamaTurn readStreamingResponse(InputStream inputStream,
			SpecterStreamingResponseListener listener, AtomicBoolean canceled) throws IOException {
		StringBuilder content = new StringBuilder();
		StringBuilder thinking = new StringBuilder();
		List<Map<String, Object>> toolCalls = new ArrayList<>();
		SpecterTokenUsage tokenUsage = null;

		try (BufferedReader reader = new BufferedReader(
			new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
			String line;
			while ((line = reader.readLine()) != null) {
				throwIfCanceled(canceled);
				String trimmed = line.trim();
				if (trimmed.isEmpty()) {
					continue;
				}

				Map<?, ?> chunk = Json.fromJson(trimmed, Map.class);
				String error = stringValue(chunk.get("error"));
				if (!error.isEmpty()) {
					throw new IllegalStateException(error);
				}

				Map<?, ?> message = mapValue(chunk.get("message"));
				String partialThinking = stringValue(message.get("thinking"));
				if (!partialThinking.isEmpty()) {
					thinking.append(partialThinking);
					listener.onPartialThinking(partialThinking);
				}

				String partialResponse = stringValue(message.get("content"));
				if (!partialResponse.isEmpty()) {
					content.append(partialResponse);
					listener.onPartialResponse(partialResponse);
				}

				toolCalls.addAll(toolCalls(message.get("tool_calls")));
				tokenUsage = SpecterTokenUsage.of(
					integerValue(chunk.get("prompt_eval_count")),
					integerValue(chunk.get("eval_count")),
					null);
			}
		}

		Map<String, Object> assistantMessage = new LinkedHashMap<>();
		assistantMessage.put("role", "assistant");
		assistantMessage.put("content", content.toString());
		if (thinking.length() > 0) {
			assistantMessage.put("thinking", thinking.toString());
		}
		if (!toolCalls.isEmpty()) {
			assistantMessage.put("tool_calls", toolCalls);
		}

		return new OllamaTurn(content.toString(), thinking.toString(), toolCalls, assistantMessage,
			tokenUsage);
	}

	private String readFailureMessage(HttpResponse<InputStream> response) throws IOException {
		String body = new String(response.body().readAllBytes(), StandardCharsets.UTF_8).trim();
		String error = "";
		if (!body.isEmpty()) {
			try {
				Map<?, ?> parsed = Json.fromJson(body, Map.class);
				error = stringValue(parsed.get("error"));
			}
			catch (RuntimeException e) {
				// Fall back to the raw body below.
			}
		}
		if (!error.isEmpty()) {
			return error;
		}
		if (!body.isEmpty()) {
			return "Ollama request failed (" + response.statusCode() + "): " + body;
		}
		return "Ollama request failed with status " + response.statusCode();
	}

	private Object resolveThinkValue() {
		String reasoningEffort = configuration.reasoningEffort();
		if (reasoningEffort != null && !"none".equalsIgnoreCase(reasoningEffort)) {
			return reasoningEffort;
		}
		if (Boolean.TRUE.equals(configuration.returnThinking())) {
			return "medium";
		}
		return null;
	}

	private void addToolResults(List<Map<String, Object>> messages,
			List<Map<String, Object>> toolCalls,
			SpecterStreamingResponseListener listener) {
		for (Map<String, Object> toolCall : toolCalls) {
			Map<?, ?> function = mapValue(toolCall.get("function"));
			String toolName = stringValue(function.get("name"));
			String argumentsJson = Json.toJson(mapValue(function.get("arguments")));
			listener.onToolCall(toolName, argumentsJson);
			dev.langchain4j.agent.tool.ToolExecutionRequest request =
				dev.langchain4j.agent.tool.ToolExecutionRequest.builder()
						.id(toolName)
						.name(toolName)
						.arguments(argumentsJson)
						.build();
			String result = toolHost.execute(request);
			listener.onToolResult(toolName, result);
			Map<String, Object> toolMessage = new LinkedHashMap<>();
			toolMessage.put("role", "tool");
			toolMessage.put("tool_name", toolName);
			toolMessage.put("content", result);
			messages.add(toolMessage);
		}
	}

	private Map<String, Object> systemMessage() {
		Map<String, Object> message = new LinkedHashMap<>();
		message.put("role", "system");
		message.put("content", systemPrompt);
		return message;
	}

	private static Map<String, Object> chatMessage(SpecterChatMessage message) {
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("role", message.role().name().toLowerCase());
		map.put("content", message.text());
		if (message.hasThinking()) {
			map.put("thinking", message.thinking());
		}
		return map;
	}

	private static List<Map<String, Object>> toOllamaTools(List<ToolSpecification> toolSpecifications) {
		List<Map<String, Object>> tools = new ArrayList<>();
		for (ToolSpecification specification : toolSpecifications) {
			Map<String, Object> function = new LinkedHashMap<>();
			function.put("name", specification.name());
			function.put("description", specification.description());
			function.put("parameters", Json.fromJson(Json.toJson(specification.parameters()), Map.class));

			Map<String, Object> tool = new LinkedHashMap<>();
			tool.put("type", "function");
			tool.put("function", function);
			tools.add(tool);
		}
		return tools;
	}

	private static List<Map<String, Object>> toolCalls(Object value) {
		if (!(value instanceof List<?> list)) {
			return List.of();
		}
		List<Map<String, Object>> toolCalls = new ArrayList<>();
		for (Object item : list) {
			Map<String, Object> copied = new LinkedHashMap<>();
			for (Map.Entry<?, ?> entry : mapValue(item).entrySet()) {
				if (entry.getKey() instanceof String key) {
					copied.put(key, entry.getValue());
				}
			}
			toolCalls.add(copied);
		}
		return toolCalls;
	}

	private static Map<?, ?> mapValue(Object value) {
		return value instanceof Map<?, ?> map ? map : Map.of();
	}

	private static String stringValue(Object value) {
		return value instanceof String text ? text : "";
	}

	private static Integer integerValue(Object value) {
		if (value instanceof Number number) {
			return number.intValue();
		}
		return null;
	}

	private static void throwIfCanceled(AtomicBoolean canceled) {
		if (canceled.get()) {
			throw new CancellationException("Request canceled");
		}
	}

	private record OllamaTurn(String content, String thinking, List<Map<String, Object>> toolCalls,
			Map<String, Object> assistantMessage, SpecterTokenUsage tokenUsage) {
	}
}
