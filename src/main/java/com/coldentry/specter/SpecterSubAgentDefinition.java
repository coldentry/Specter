package com.coldentry.specter;

import java.util.Objects;

record SpecterSubAgentDefinition(String name, String description, String instructions) {

	SpecterSubAgentDefinition {
		name = normalize(name);
		description = normalize(description);
		instructions = normalize(instructions);
		Objects.requireNonNull(name, "name");
		Objects.requireNonNull(instructions, "instructions");
	}

	private static String normalize(String value) {
		if (value == null) {
			return null;
		}
		String trimmed = value.trim();
		return trimmed.isEmpty() ? null : trimmed;
	}
}
