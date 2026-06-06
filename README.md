# Specter

Specter is a Ghidra extension by Cold Entry LLC for agent-assisted reverse engineering. It adds a dockable terminal-style chat panel inside Ghidra and gives the model tool access to the active program so it can answer questions with Specter DSL queries, datatype tools, sub-agents, and targeted edit tools instead of guessing.

## Current Capabilities

- Dockable `Specter` provider that opens inside the Ghidra tool window.
- Terminal-style chat UI with prompt history and slash commands.
- Model profile management stored in Java preferences.
- Sub-agent definitions stored in Java preferences and invocable by the model.
- OpenAI-compatible chat backend support.
- Native Ollama chat backend support.
- Streaming assistant replies and optional streaming thinking output.
- Per-turn token usage display when the backend reports it.
- Tool-backed program context for the active binary.
- Semi-deterministic workflows with SQL-like syntax over the active program.

## Available Ghidra Tools

The assistant can currently call these tools against the active program:

- `RunSpecterDslQuery`
- `GetCurrentAddress`
- `SetListingComment`
- `SetDecompilerComment`
- `RenameFunctionParameter`
- `RetypeFunctionParameter`
- `RenameFunctionLocalVariable`
- `CreateFunction`
- `RetypeGlobalData`
- `RetypeLocalVariable`
- `SearchDataTypesByNameRegex`
- `GetDataTypeDetails`
- `CreateStructureDataType`
- `ModifyStructureDataType`

`RunSpecterDslQuery` is the primary read path for functions, symbols, strings, defined data, references, decompilation, instruction listings, grouping, ordering, and DSL loops. It can also run supported DSL updates such as `UPDATE FUNCTION`. The dedicated edit tools update the active program database directly and record edits with Ghidra `SourceType.AI`; before one of those edit-tool changes is applied, Specter prompts the user to approve or deny the specific change and can remember approval on a per-tool basis for future runs. The system prompt also includes the active binary name, Ghidra language specifier, and a heuristic `Likely stripped: yes|no` status based on the share of auto-named `FUN_` functions when a program is open.

## Terminal Commands

- `/help` shows the available commands.
- `/model` opens the model configuration dialog.
- `/new` clears the current conversation context.
- `/subagent` opens the sub-agent configuration dialog.
- `/resetprefs` clears Specter preferences after confirmation.
- `/thinking` toggles thinking visibility.
- `/thinking show|hide|toggle` explicitly controls thinking visibility.
- `/dsl <script>` runs Specter DSL or SQL-like statements against the active program.
  End `/dsl` scripts with `;` to submit; Enter adds another line until then.

Thinking is hidden by default in the terminal, but it can be shown from the slash command or the local provider action.

## Semi-Deterministic Workflows

Specter includes a `/dsl` command for expressing repeatable analysis workflows with SQL-like syntax. The goal is to make the deterministic part of reverse engineering explicit: select the functions you care about, group or order them by program facts, inspect decompilation, then use that output as stable context for human or LLM-driven decisions.

The DSL is intentionally SQL-shaped. Plain SQL is the subset, and Specter-specific workflow primitives can be layered on top as needed. Current support centers on the `FUNCTION`, `STRING`, and `DATA` virtual tables:

```sql
SELECT name, entry FROM FUNCTION WHERE name LIKE 'FUN_%' ORDER BY entry LIMIT 20;
SELECT name, entry FROM FUNCTION WHERE name NOT LIKE 'FUN_%' ORDER BY entry LIMIT 20;
SELECT name, entry FROM FUNCTION WHERE is_thunk = false AND name NOT LIKE 'FUN_%' LIMIT 20;
SELECT name, entry FROM FUNCTION WHERE is_external = true OR (is_thunk = false AND name NOT LIKE 'FUN_%') LIMIT 20;
SELECT entry, name FROM FUNCTION WHERE entry >= 0x4044d1;
SELECT entry, name, callgraph_level(entry) FROM FUNCTION ORDER BY callgraph_level(entry) DESC LIMIT 50;
SELECT entry, name, decompilation(entry) FROM FUNCTION WHERE entry = 0x4044d1;
SELECT entry, name, instructions(entry) FROM FUNCTION WHERE entry = 0x4044d1;
SELECT count(1) func_count FROM FUNCTION;
SELECT callgraph_level(entry) lvl, count(*) FROM FUNCTION GROUP BY lvl;
SELECT * FROM STRING WHERE value LIKE 'usage:%';
SELECT address, value, length FROM STRING WHERE value LIKE '%http%' ORDER BY address LIMIT 20;
SELECT address, name, data_type, value_text FROM DATA WHERE is_global = true ORDER BY address LIMIT 20;
SELECT address, data_type, value FROM DATA WHERE is_constant = true ORDER BY address LIMIT 20;
```

The first write-capable SQL statement is a narrow function rename primitive:

```sql
UPDATE FUNCTION
SET name = 'parse_header'
WHERE entry = 0x4044d1;
```

`UPDATE` currently only supports `FUNCTION.name`, requires a `WHERE` clause, and records renames with Ghidra `SourceType.AI`.

This is useful for bottom-up workflows. For example, group functions by their callgraph level to see how many functions exist at each layer:

```sql
SELECT callgraph_level(entry) lvl, count(*) func_count
FROM FUNCTION
GROUP BY lvl;
```

Inspect leaf-side functions first by sorting from higher callgraph levels down:

```sql
SELECT entry, name, callgraph_level(entry) lvl
FROM FUNCTION
WHERE name LIKE 'FUN_%'
ORDER BY callgraph_level(entry) DESC
LIMIT 25;
```

Fetch decompilation for a specific function directly from the same query surface:

```sql
SELECT entry, name, decompilation(entry) c
FROM FUNCTION
WHERE entry = 0x4044d1;
```

Fetch the corresponding instruction listing the same way:

```sql
SELECT entry, name, instructions(entry) listing
FROM FUNCTION
WHERE entry = 0x4044d1;
```

The DSL also supports a minimal loop for batching one query over values produced by another query:

```text
FOR level IN SELECT callgraph_level(entry) FROM FUNCTION ORDER BY callgraph_level(entry) DESC LIMIT 2; DO SELECT entry, name FROM FUNCTION WHERE callgraph_level(entry) = :level LIMIT 5; END;
```

Supported `FUNCTION` columns are `entry`, `name`, `namespace`, `signature`, `return_type`, `parameter_count`, `body_min`, `body_max`, `body_size`, `is_external`, `is_thunk`, `calling_convention`, and `source`.
Supported `STRING` columns are `address`, `value`, `data_type`, and `length`.
Supported `DATA` columns are `address`, `name`, `namespace`, `data_type`, `base_data_type`, `length`, `value`, `value_text`, `is_constant`, `is_writable`, `is_volatile`, `is_pointer`, `is_array`, `is_string`, `is_global`, `containing_function`, `source`, and `reference_count`.
Numeric literals may be decimal or hexadecimal.
`WHERE` supports single predicates plus `AND`, `OR`, and parentheses. `AND` binds tighter than `OR`.
The `count(*)`, `count(1)`, and `count(column)` aggregate built-ins count matched rows.
Select expressions may use `AS alias` or a bare alias, for example `SELECT count(1) func_count FROM FUNCTION;`.
`GROUP BY` supports selected aliases and expressions, for example `SELECT callgraph_level(entry) lvl, count(*) FROM FUNCTION GROUP BY lvl;`.
Grouped output is sorted by group key by default, with `NULL` groups last.
The `callgraph_level(entry)` built-in computes an acyclic callgraph level using Ghidra's `AcyclicCallGraphBuilder`; root and entry-point functions are level `0`, and callees increase in level.
The `decompilation(entry)` and `instructions(entry)` built-ins are supported in the `SELECT` list and render multiline row blocks.

## Model Configuration

Use `/model` to manage one or more saved model profiles. Each profile stores:

- provider (`OpenAI-compatible` or `Ollama native`)
- endpoint/base URL
- model name
- API key
- optional thinking return flag
- optional reasoning effort

For llama.cpp's OpenAI-compatible server, choose `OpenAI-compatible`, set the endpoint to
`http://127.0.0.1:8080/v1` or the matching `/v1` base URL for your server, leave the API key
blank unless your server requires one, and use the model name or alias exposed by llama.cpp.

## Sub-Agent Configuration

Use `/subagent` to manage saved sub-agents. Each sub-agent stores:

- name
- optional description
- instructions/prompt for delegated work

Specter seeds several sub-agents by default on first run:

- `Explore` gathers surrounding function and callgraph context from references, decompilation, listing, symbols, and related function discovery.
- `SummarizeFunction` summarizes one function's behavior, inputs, outputs, and side effects.
- `StringsAndXrefs` finds relevant strings and references, then identifies the functions worth inspecting next.
- `Types` inspects parameters, locals, globals, and structures to propose datatype improvements.
- `Naming` proposes better names for functions, parameters, locals, and globals from behavioral context.
- `Callgraph` maps callers, callees, fan-in, fan-out, and the likely control-flow role of a function.

The main assistant can use tools to list the configured sub-agents, inspect one sub-agent's saved instructions, and invoke one by name for a delegated task.

Specter chooses its backend from the configured provider:

- OpenAI-compatible endpoints use the LangChain4j OpenAI streaming client.
- Ollama-style endpoints use the native Ollama `/api/chat` path.

Existing saved profiles that do not yet have a provider are migrated by endpoint shape: clear
Ollama-native endpoints continue using `/api/chat`, while local `/v1` endpoints such as llama.cpp
are treated as OpenAI-compatible.

## Build

Set `GHIDRA_INSTALL_DIR` to your local Ghidra installation and run Gradle from this repository.

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
gradle buildExtension
```

To create a distributable extension zip:

```bash
gradle distributeExtension
```

The current project expects a local Ghidra install and uses the bundled Ghidra extension Gradle support from that installation.

## Project Layout

- `src/main/java/com/coldentry/specter/` contains the plugin, UI, model configuration, chat services, and Ghidra tool adapters.
- `src/main/help/help/topics/specter/` contains the in-tool Ghidra help topic.
- `build.gradle` builds the extension against a local Ghidra install.
- `extension.properties` defines the extension metadata.

## Scope

This is no longer just an extension skeleton. The repository already contains a working interactive chat panel, model configuration workflow, backend selection between OpenAI-compatible services and Ollama, and a first pass at Ghidra-aware agent tools. The current scope now includes both inspection and targeted annotation edits inside the active code browser context, but it is still not trying to become a broader autonomous workflow engine.
