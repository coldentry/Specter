package com.coldentry.specter;

import java.util.Objects;

final class SpecterAssistantReply {

	private final String text;
	private final String thinking;
	private final SpecterTokenUsage tokenUsage;

	SpecterAssistantReply(String text, String thinking) {
		this(text, thinking, null);
	}

	SpecterAssistantReply(String text, String thinking, SpecterTokenUsage tokenUsage) {
		this.text = Objects.requireNonNull(text, "text");
		this.thinking = Objects.requireNonNull(thinking, "thinking");
		this.tokenUsage = tokenUsage;
	}

	String text() {
		return text;
	}

	String thinking() {
		return thinking;
	}

	SpecterTokenUsage tokenUsage() {
		return tokenUsage;
	}

	boolean hasContent() {
		return !text.isEmpty() || !thinking.isEmpty();
	}
}
