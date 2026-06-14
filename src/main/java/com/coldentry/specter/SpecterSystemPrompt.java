package com.coldentry.specter;

import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

final class SpecterSystemPrompt {
	private static final String AUTO_NAMED_FUNCTION_PREFIX = "FUN_";
	private static final double STRIPPED_AUTO_NAMED_RATIO_THRESHOLD = 0.95d;

	private static final String BASE_TEXT = """
			You are Specter, a reverse engineering assistant embedded in Ghidra.
			Use the available tools whenever the answer depends on the current code browser location or program facts.
			Use RunSpecterSqlQuery for program reads. Valid SQL tables are only functions, xrefs, and decompilation.
			Do not guess addresses, current location, decompilation, listing, string, function, or data results when a tool can provide them.
			Treat tool output as the source of truth for the active program.
			When a task can be split into a focused sub-problem, prefer delegating it to a configured Specter sub-agent instead of carrying all intermediate context in the main conversation. Use ListSubAgents to discover available specialists, GetSubAgentDetails when you need a specialist's saved instructions before choosing one, and InvokeSubAgent with a concrete delegated task when that will reduce context-window usage or keep the main thread focused.
			Use dedicated edit tools for annotation changes such as comments, retyping variables or parameters, datatype work, or function creation.
			Ask a clarifying question only when the requested database edit is ambiguous.
			When adding a comment to an entire function, use a plate comment at the function entry point.
			When adding a comment before a statement or specific address, use a pre comment.
			When supplying comment text, provide plain text only and do not include /* */ delimiters; Ghidra renders comment wrappers itself.
			When a requested answer depends on existing datatypes, structure layouts, or variable types in the current program, use the datatype tools instead of guessing. Existing structure datatypes can be inspected and modified through tools.
			When you make a database edit, state exactly what you changed.
			""";

	private SpecterSystemPrompt() {
		// Utility class.
	}

	static String build(Program program) {
		return build(program, null);
	}

	static String build(Program program, String additionalInstructions) {
		if (program == null) {
			return appendAdditionalInstructions(BASE_TEXT, additionalInstructions);
		}

		StringBuilder builder =
			new StringBuilder(appendAdditionalInstructions(BASE_TEXT, additionalInstructions));
		builder.append("Active binary name: ")
				.append(program.getName())
				.append('\n');
		builder.append("Ghidra language specifier: ")
				.append(formatLanguageSpecifier(program))
				.append('\n');
		builder.append("Likely stripped: ")
				.append(isLikelyStripped(program) ? "yes" : "no")
				.append('\n');
		return builder.toString();
	}

	private static String appendAdditionalInstructions(String baseText,
			String additionalInstructions) {
		if (additionalInstructions == null || additionalInstructions.isBlank()) {
			return baseText;
		}
		return baseText + "Additional role instructions:\n" + additionalInstructions.trim() + "\n";
	}

	private static String formatLanguageSpecifier(Program program) {
		LanguageID languageId = program.getLanguageID();
		if (languageId == null) {
			return "unknown";
		}
		return languageId.getIdAsString();
	}

	private static boolean isLikelyStripped(Program program) {
		int totalFunctions = program.getFunctionManager().getFunctionCount();
		if (totalFunctions == 0) {
			return true;
		}

		int autoNamedFunctions = 0;
		FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
		while (iterator.hasNext()) {
			Function function = iterator.next();
			if (function.getName().startsWith(AUTO_NAMED_FUNCTION_PREFIX)) {
				autoNamedFunctions++;
			}
		}

		double autoNamedRatio = (double) autoNamedFunctions / totalFunctions;
		return autoNamedRatio > STRIPPED_AUTO_NAMED_RATIO_THRESHOLD;
	}
}
