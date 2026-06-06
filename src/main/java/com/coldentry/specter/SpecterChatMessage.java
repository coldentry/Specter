package com.coldentry.specter;

import java.util.Objects;

final class SpecterChatMessage {

	enum Role {
		USER,
		ASSISTANT
	}

	private final Role role;
	private final String text;
	private final String thinking;

	private SpecterChatMessage(Role role, String text, String thinking) {
		this.role = Objects.requireNonNull(role, "role");
		this.text = Objects.requireNonNull(text, "text");
		this.thinking = Objects.requireNonNull(thinking, "thinking");
	}

	static SpecterChatMessage user(String text) {
		return new SpecterChatMessage(Role.USER, text, "");
	}

	static SpecterChatMessage assistant(String text) {
		return assistant(text, "");
	}

	static SpecterChatMessage assistant(String text, String thinking) {
		return new SpecterChatMessage(Role.ASSISTANT, text, thinking);
	}

	Role role() {
		return role;
	}

	String text() {
		return text;
	}

	String thinking() {
		return thinking;
	}

	boolean hasThinking() {
		return !thinking.isEmpty();
	}
}
