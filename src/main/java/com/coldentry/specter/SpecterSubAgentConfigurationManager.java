package com.coldentry.specter;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

final class SpecterSubAgentConfigurationManager {

	private static final String INITIALIZED_KEY = "subAgents.initialized";
	private static final String DEFAULTS_VERSION_KEY = "subAgents.defaultsVersion";
	private static final int CURRENT_DEFAULTS_VERSION = 2;
	private static final String AGENT_COUNT_KEY = "subAgents.count";
	private static final String AGENT_PREFIX = "subAgents.";
	private static final String NAME_SUFFIX = ".name";
	private static final String DESCRIPTION_SUFFIX = ".description";
	private static final String INSTRUCTIONS_SUFFIX = ".instructions";

	private final Preferences preferences =
		Preferences.userNodeForPackage(SpecterSubAgentConfigurationManager.class);
	private volatile List<SpecterSubAgentDefinition> definitions = loadDefinitions();

	Snapshot snapshot() {
		return new Snapshot(definitions);
	}

	void reloadFromPreferences() {
		try {
			preferences.sync();
		}
		catch (BackingStoreException e) {
			throw new IllegalStateException("Unable to reload sub-agent definitions", e);
		}
		definitions = loadDefinitions();
	}

	List<SpecterSubAgentDefinition> definitions() {
		return definitions;
	}

	SpecterSubAgentDefinition findByName(String name) {
		if (name == null) {
			return null;
		}
		String normalized = name.trim();
		if (normalized.isEmpty()) {
			return null;
		}
		for (SpecterSubAgentDefinition definition : definitions) {
			if (definition.name().equalsIgnoreCase(normalized)) {
				return definition;
			}
		}
		return null;
	}

	void updateDefinitions(List<SpecterSubAgentDefinition> newDefinitions) {
		List<SpecterSubAgentDefinition> validated = validateDefinitions(newDefinitions);
		storeDefinitions(validated);
		definitions = validated;
	}

	private List<SpecterSubAgentDefinition> loadDefinitions() {
		if (!preferences.getBoolean(INITIALIZED_KEY, false)) {
			List<SpecterSubAgentDefinition> seededDefinitions = loadStoredDefinitions();
			if (seededDefinitions.isEmpty()) {
				seededDefinitions = defaultDefinitions();
			}
			storeDefinitions(seededDefinitions);
			return seededDefinitions;
		}

		List<SpecterSubAgentDefinition> storedDefinitions = loadStoredDefinitions();
		if (preferences.getInt(DEFAULTS_VERSION_KEY, 1) < CURRENT_DEFAULTS_VERSION) {
			List<SpecterSubAgentDefinition> mergedDefinitions =
				mergeMissingDefaults(storedDefinitions);
			storeDefinitions(mergedDefinitions);
			return mergedDefinitions;
		}
		return storedDefinitions;
	}

	private List<SpecterSubAgentDefinition> loadStoredDefinitions() {
		int count = preferences.getInt(AGENT_COUNT_KEY, 0);
		if (count <= 0) {
			return List.of();
		}

		List<SpecterSubAgentDefinition> loaded = new ArrayList<>(count);
		for (int i = 0; i < count; i++) {
			String keyPrefix = AGENT_PREFIX + i;
			String name = preferences.get(keyPrefix + NAME_SUFFIX, null);
			String instructions = preferences.get(keyPrefix + INSTRUCTIONS_SUFFIX, null);
			if (name == null || name.isBlank() || instructions == null || instructions.isBlank()) {
				continue;
			}
			loaded.add(new SpecterSubAgentDefinition(name,
				preferences.get(keyPrefix + DESCRIPTION_SUFFIX, null), instructions));
		}
		return List.copyOf(loaded);
	}

	private List<SpecterSubAgentDefinition> defaultDefinitions() {
		return List.of(
			new SpecterSubAgentDefinition(
				"Explore",
				"Gather surrounding function and callgraph context before deeper analysis.",
				"""
				Start by grounding yourself in the current code browser context. Use GetCurrentAddress if the delegated task does not already include an address.

				Build a quick exploration summary using the available program tools:
				- identify the relevant function or symbol
				- inspect the current function with RunSpecterSqlQuery over the functions and decompilation tables.
				- inspect xrefs with RunSpecterSqlQuery joining REFERENCES to FUNCTIONS to understand who calls or reaches it

				Focus on callgraph-oriented context:
				- entry points and nearby functions
				- callers and likely callees visible from names, references, and decompilation
				- important strings, symbols, or datatypes that shape the behavior

				Return a concise exploration report for the parent agent. Include concrete function names, addresses, and why each item matters. Do not make database edits.
				"""),
			new SpecterSubAgentDefinition(
				"SummarizeFunction",
				"Summarize one function's behavior, inputs, outputs, and side effects.",
				"""
				Start by grounding yourself in the current code browser context. Use GetCurrentAddress if the delegated task does not already include an address.

				Focus on a single function unless the task explicitly asks for a comparison.
				- inspect the function with RunSpecterDslQuery over FUNCTION using decompilation(entry) in the SELECT list, and use instructions(entry) there when assembly details matter
				- identify likely inputs, outputs, side effects, important branches, and notable callees
				- mention strings, globals, or datatypes only when they materially affect the behavior

				Return a concise function summary with:
				- the function name and entry address
				- a plain-language purpose statement
				- likely inputs and outputs
				- important side effects or state changes
				- a short confidence note for uncertain conclusions

				Do not make database edits.
				"""),
			new SpecterSubAgentDefinition(
				"StringsAndXrefs",
				"Find relevant strings and references, then identify the functions worth inspecting next.",
				"""
				Start by grounding yourself in the current code browser context. Use GetCurrentAddress if the delegated task does not already include an address.

				When the task names a string pattern, use RunSpecterDslQuery over STRING to find candidate strings. For each relevant match:
				- identify the string address and value
				- inspect its inbound references with RunSpecterDslQuery over REFERENCE
				- pivot into the most relevant referencing functions with RunSpecterDslQuery over FUNCTION or SYMBOL; use decompilation(entry) or instructions(entry) as SELECT expressions when needed

				Keep the output selective. Do not dump every match. Return:
				- the most relevant strings and addresses
				- the key referencing functions or code locations
				- why each reference matters
				- the small set of next functions the parent agent should inspect

				Do not make database edits.
				"""),
			new SpecterSubAgentDefinition(
				"Types",
				"Inspect parameters, locals, globals, and structures to propose likely datatype improvements.",
				"""
				Start by grounding yourself in the current code browser context. Use GetCurrentAddress if the delegated task does not already include an address.

				Focus on type recovery and structure understanding:
				- inspect the target function with RunSpecterDslQuery over FUNCTION using decompilation(entry) or instructions(entry) in the SELECT list
				- inspect globals and constants with RunSpecterDslQuery over DATA
				- inspect known datatypes with SearchDataTypesByNameRegex and GetDataTypeDetails when the task touches structures or typedef-like names
				- reason about likely parameter, local, global, pointer, array, and structure field types from access patterns and call usage

				Return a concise type analysis with:
				- the symbols or variables reviewed
				- likely current type problems or ambiguities
				- recommended datatype or structure improvements
				- brief justification tied to observed accesses or calls

				Do not make database edits unless the delegated task explicitly asks for them.
				"""),
			new SpecterSubAgentDefinition(
				"Naming",
				"Propose better names for functions, parameters, locals, and globals from behavioral context.",
				"""
				Start by grounding yourself in the current code browser context. Use GetCurrentAddress if the delegated task does not already include an address.

				Focus on naming quality rather than broad analysis:
				- inspect behavior with RunSpecterDslQuery over FUNCTION using decompilation(entry) or instructions(entry) in the SELECT list
				- use RunSpecterDslQuery over FUNCTION, STRING, DATA, REFERENCE joins, and SYMBOL when those help infer intent
				- infer names from observable behavior, data flow, strings, constants, and caller or callee relationships

				Return a concise naming report with:
				- each symbol under consideration
				- one preferred name
				- optional alternative names when ambiguity remains
				- brief justification for each proposal

				Do not make database edits unless the delegated task explicitly asks for them.
				"""),
			new SpecterSubAgentDefinition(
				"Callgraph",
				"Map callers, callees, fan-in, fan-out, and the likely control-flow role of a function.",
				"""
				Start by grounding yourself in the current code browser context. Use GetCurrentAddress if the delegated task does not already include an address.

				Stay focused on control-flow relationships:
				- inspect the target function with RunSpecterDslQuery over FUNCTION using decompilation(entry) or instructions(entry) in the SELECT list
				- use RunSpecterDslQuery joining REFERENCE to FUNCTION to identify callers or inbound references
				- use RunSpecterDslQuery over FUNCTION, SYMBOL, or REFERENCE joins to pivot to likely callees or related functions by name

				Return a concise callgraph report with:
				- the target function name and address
				- the most important callers and callees
				- whether the function looks like an entry point, dispatcher, wrapper, helper, sink, or leaf
				- any small clusters of related functions the parent agent should inspect together

				Do not make database edits.
				"""));
	}

	private List<SpecterSubAgentDefinition> mergeMissingDefaults(
			List<SpecterSubAgentDefinition> existingDefinitions) {
		List<SpecterSubAgentDefinition> merged = new ArrayList<>(existingDefinitions);
		Set<String> existingNames = new LinkedHashSet<>();
		for (SpecterSubAgentDefinition definition : existingDefinitions) {
			existingNames.add(definition.name().toLowerCase(Locale.ROOT));
		}
		for (SpecterSubAgentDefinition defaultDefinition : defaultDefinitions()) {
			if (existingNames.add(defaultDefinition.name().toLowerCase(Locale.ROOT))) {
				merged.add(defaultDefinition);
			}
		}
		return List.copyOf(merged);
	}

	private List<SpecterSubAgentDefinition> validateDefinitions(
			List<SpecterSubAgentDefinition> newDefinitions) {
		if (newDefinitions == null) {
			return List.of();
		}

		Set<String> names = new LinkedHashSet<>();
		List<SpecterSubAgentDefinition> validated = new ArrayList<>(newDefinitions.size());
		for (SpecterSubAgentDefinition definition : newDefinitions) {
			if (definition == null) {
				continue;
			}
			if (definition.name() == null) {
				throw new IllegalArgumentException("Each sub-agent needs a name.");
			}
			if (definition.instructions() == null) {
				throw new IllegalArgumentException(
					"Sub-agent '" + definition.name() + "' needs instructions.");
			}
			String canonicalName = definition.name().toLowerCase(Locale.ROOT);
			if (!names.add(canonicalName)) {
				throw new IllegalArgumentException(
					"Sub-agent names must be unique. Duplicate name: " + definition.name());
			}
			validated.add(definition);
		}
		return List.copyOf(validated);
	}

	private void storeDefinitions(List<SpecterSubAgentDefinition> newDefinitions) {
		int existingCount = preferences.getInt(AGENT_COUNT_KEY, 0);
		for (int i = 0; i < Math.max(existingCount, newDefinitions.size()); i++) {
			String keyPrefix = AGENT_PREFIX + i;
			if (i >= newDefinitions.size()) {
				preferences.remove(keyPrefix + NAME_SUFFIX);
				preferences.remove(keyPrefix + DESCRIPTION_SUFFIX);
				preferences.remove(keyPrefix + INSTRUCTIONS_SUFFIX);
				continue;
			}

			SpecterSubAgentDefinition definition = newDefinitions.get(i);
			preferences.put(keyPrefix + NAME_SUFFIX, definition.name());
			putNullable(keyPrefix + DESCRIPTION_SUFFIX, definition.description());
			preferences.put(keyPrefix + INSTRUCTIONS_SUFFIX, definition.instructions());
		}

		preferences.putBoolean(INITIALIZED_KEY, true);
		preferences.putInt(DEFAULTS_VERSION_KEY, CURRENT_DEFAULTS_VERSION);
		preferences.putInt(AGENT_COUNT_KEY, newDefinitions.size());
		try {
			preferences.flush();
		}
		catch (BackingStoreException e) {
			throw new IllegalStateException("Unable to persist sub-agent definitions", e);
		}
	}

	private void putNullable(String key, String value) {
		if (value == null) {
			preferences.remove(key);
			return;
		}
		preferences.put(key, value);
	}

	record Snapshot(List<SpecterSubAgentDefinition> definitions) {
		Snapshot {
			definitions = List.copyOf(definitions);
		}
	}
}
