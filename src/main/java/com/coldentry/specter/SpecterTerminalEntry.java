package com.coldentry.specter;

import java.util.Objects;

final class SpecterTerminalEntry {

	enum Kind {
		OUTPUT,
		USER,
		ASSISTANT,
		TOOL_CALL,
		TOOL_RESULT
	}

	private final Kind kind;
	private final String text;
	private final String thinking;
	private final String toolArguments;
	private final String prompt;

	private SpecterTerminalEntry(Kind kind, String text, String thinking, String toolArguments,
			String prompt) {
		this.kind = Objects.requireNonNull(kind, "kind");
		this.text = Objects.requireNonNull(text, "text");
		this.thinking = Objects.requireNonNull(thinking, "thinking");
		this.toolArguments = Objects.requireNonNull(toolArguments, "toolArguments");
		this.prompt = Objects.requireNonNull(prompt, "prompt");
	}

	static SpecterTerminalEntry output(String text) {
		return new SpecterTerminalEntry(Kind.OUTPUT, text, "", "", "");
	}

	static SpecterTerminalEntry user(String text, String prompt) {
		return new SpecterTerminalEntry(Kind.USER, text, "", "", prompt);
	}

	static SpecterTerminalEntry assistant(String text, String thinking) {
		return new SpecterTerminalEntry(Kind.ASSISTANT, text, thinking, "", "");
	}

	static SpecterTerminalEntry toolCall(String name, String arguments) {
		return new SpecterTerminalEntry(Kind.TOOL_CALL, name, "", arguments, "");
	}

	static SpecterTerminalEntry toolResult(String result) {
		return new SpecterTerminalEntry(Kind.TOOL_RESULT, result, "", "", "");
	}

	Kind kind() {
		return kind;
	}

	String text() {
		return text;
	}

	String thinking() {
		return thinking;
	}

	String toolArguments() {
		return toolArguments;
	}

	String prompt() {
		return prompt;
	}
}
