package com.coldentry.specter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.internal.Json;
import dev.langchain4j.model.chat.request.json.JsonArraySchema;
import dev.langchain4j.model.chat.request.json.JsonObjectSchema;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.data.DataTypeParser;
import ghidra.util.task.TaskMonitor;

final class SpecterCodeBrowserTools implements SpecterToolHost {

	private static final int DECOMPILATION_TIMEOUT_SECONDS = 30;
	private static final int MAX_DATA_TYPE_SEARCH_RESULTS = 200;
	private static final int MAX_TOOL_RESPONSE_LENGTH = 32_000;
	private static final SourceType EDIT_SOURCE_TYPE = SourceType.AI;

	private final SpecterPlugin plugin;
	private final SpecterSubAgentConfigurationManager subAgentConfigurationManager;
	private final SpecterDatabaseEditPreferences databaseEditPreferences =
		new SpecterDatabaseEditPreferences();
	private SpecterDslService dslService;
	private final SpecterToolHost coreToolHost = new SpecterToolHost() {
		@Override
		public Program currentProgram() {
			return SpecterCodeBrowserTools.this.currentProgram();
		}

		@Override
		public List<ToolSpecification> toolSpecifications() {
			return coreToolSpecifications;
		}

		@Override
		public String execute(ToolExecutionRequest request) {
			return SpecterCodeBrowserTools.this.execute(request);
		}
	};
	private BiFunction<String, String, String> subAgentExecutor = (name, task) -> {
		throw new IllegalStateException("Sub-agent execution is unavailable.");
	};
	private final List<ToolSpecification> coreToolSpecifications = List.of(
		ToolSpecification.builder()
				.name("RunSpecterDslQuery")
				.description(
					"Run a Specter DSL query against the active program. Valid tables are only FUNCTION, STRING, DATA, REFERENCE, and SYMBOL. instructions(entry), decompilation(entry), callgraph_level(entry), concat(...), and prompt(...) are SELECT expressions, not tables; for assembly use SELECT entry, name, instructions(entry) FROM FUNCTION WHERE entry = 0x...;. Use JOIN for caller/callee queries. For call references, use type IN ('COMPUTED_CALL', 'UNCONDITIONAL_CALL'); there is no generic CALL type. UPDATE FUNCTION, DATA, and SYMBOL are supported for listing renames. Database-writing UPDATE statements are approval-gated by Specter, so call this tool directly when the user requests a clear rename.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("query",
							"Specter DSL or SQL query ending with ';', for example SELECT entry, name FROM FUNCTION WHERE name LIKE 'FUN_%' LIMIT 20;")
						.required("query")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("GetCurrentAddress")
				.description("Get the current address where the Ghidra CodeBrowser is focused.")
				.parameters(JsonObjectSchema.builder()
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("SetListingComment")
				.description(
					"Create or replace a listing comment at the given address. Valid comment_type values are eol, pre, post, plate, and repeatable. Use plate for a function-level comment at the function entry point. Use pre for a comment that should appear before a specific statement or address. Provide plain comment text only; do not include C-style comment delimiters such as /* or */.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("address",
							"Address of the code unit that should receive the listing comment.")
						.addStringProperty("comment_type",
							"Listing comment type: eol, pre, post, plate, or repeatable.")
						.addStringProperty("text",
							"Comment text to store in the listing.")
						.required("address", "comment_type", "text")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("SetDecompilerComment")
				.description(
					"Create or replace a decompiler-visible comment at the given address. Valid comment_type values are pre and plate. Use plate for a function-level comment at the function entry point. Use pre for a comment that should appear before a specific statement or address. Provide plain comment text only; do not include C-style comment delimiters such as /* or */.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("address",
							"Address of the code unit that should receive the decompiler-visible comment.")
						.addStringProperty("comment_type",
							"Decompiler comment type: pre or plate.")
						.addStringProperty("text",
							"Comment text to store for the decompiler view.")
						.required("address", "comment_type", "text")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("RenameFunctionParameter")
				.description(
					"Rename a parameter in the function containing the given address.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("function_address",
							"Address inside the target function, for example the function entry point.")
						.addStringProperty("current_name",
							"Current parameter name as shown in the decompiler or signature.")
						.addStringProperty("new_name",
							"New parameter name to apply.")
						.required("function_address", "current_name", "new_name")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("RetypeFunctionParameter")
				.description(
					"Retype a parameter in the function containing the given address using a Ghidra datatype expression.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("function_address",
							"Address inside the target function, for example the function entry point.")
						.addStringProperty("current_name",
							"Current parameter name as shown in the decompiler or signature.")
						.addStringProperty("new_type",
							"Datatype expression to apply, for example 'MyStruct *' or 'char[32]'.")
						.required("function_address", "current_name", "new_type")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("RenameFunctionLocalVariable")
				.description(
					"Rename a local variable in the function containing the given address.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("function_address",
							"Address inside the target function, for example the function entry point.")
						.addStringProperty("current_name",
							"Current local variable name as shown in the decompiler.")
						.addStringProperty("new_name",
							"New local variable name to apply.")
						.required("function_address", "current_name", "new_name")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("CreateFunction")
				.description(
					"Create a function at an address that is not already defined as a function. An optional name may also be supplied.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("address",
							"Address where the new function should start.")
						.addStringProperty("name",
							"Optional function name to apply after creation.")
						.required("address")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("RetypeGlobalData")
				.description(
					"Retype a global data item in the listing at the given address using a Ghidra datatype expression such as 'int', 'char *', 'MyStruct *', or 'byte[16]'.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("address",
							"Address of the global data item to retype.")
						.addStringProperty("new_type",
							"Datatype expression to apply, for example 'MyStruct *' or 'uint32'.")
						.required("address", "new_type")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("RetypeLocalVariable")
				.description(
					"Retype a local variable in the function containing the given address using a Ghidra datatype expression.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("function_address",
							"Address inside the target function, for example the function entry point.")
						.addStringProperty("current_name",
							"Current local variable name as shown in the decompiler.")
						.addStringProperty("new_type",
							"Datatype expression to apply, for example 'MyStruct *' or 'char[32]'.")
						.required("function_address", "current_name", "new_type")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("SearchDataTypesByNameRegex")
				.description(
					"Search program and built-in datatypes whose names match a Java regular expression.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("regex",
							"Java regular expression used to match datatype names.")
						.required("regex")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("GetDataTypeDetails")
				.description(
					"Look up an existing datatype by name or full path and return details. For structures, include defined fields.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("name_or_path",
							"Datatype name like 'IMAGE_DOS_HEADER' or full path like '/MyTypes/IMAGE_DOS_HEADER'.")
						.required("name_or_path")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("CreateStructureDataType")
				.description(
					"Create a new structure datatype in the program datatype manager. Field types use Ghidra datatype expressions.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("name",
							"New structure name.")
						.addStringProperty("category_path",
							"Optional datatype category path such as '/Specter' or '/MyTypes/Net'.")
						.addStringProperty("description",
							"Optional structure description.")
						.addProperty("fields", JsonArraySchema.builder()
								.description("Ordered structure fields.")
								.items(JsonObjectSchema.builder()
										.addStringProperty("name", "Field name.")
										.addStringProperty("type",
											"Field datatype expression such as 'uint32', 'char *', or 'byte[16]'.")
										.addStringProperty("comment", "Optional field comment.")
										.required("name", "type")
										.additionalProperties(false)
										.build())
								.build())
							.required("name", "fields")
							.additionalProperties(false)
							.build())
				.build(),
		ToolSpecification.builder()
				.name("ModifyStructureDataType")
				.description(
					"Modify an existing structure datatype. By default, new fields are appended. If replace_fields is true, the structure's defined fields are replaced with the provided ordered field list.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("name_or_path",
							"Existing structure datatype name like 'MY_STRUCT' or full path like '/Specter/MY_STRUCT'.")
						.addStringProperty("description",
							"Optional replacement description for the structure.")
						.addBooleanProperty("replace_fields",
							"If true, replace the structure's defined fields with the provided ordered field list. If false or omitted, append the provided fields.")
						.addProperty("fields", JsonArraySchema.builder()
								.description("Fields to append or use as the full replacement list.")
								.items(JsonObjectSchema.builder()
										.addStringProperty("name", "Field name.")
										.addStringProperty("type",
											"Field datatype expression such as 'uint32', 'char *', or 'byte[16]'.")
										.addStringProperty("comment", "Optional field comment.")
										.required("name", "type")
										.additionalProperties(false)
										.build())
								.build())
						.required("name_or_path")
						.additionalProperties(false)
						.build())
				.build());
	private final List<ToolSpecification> subAgentToolSpecifications = List.of(
		ToolSpecification.builder()
				.name("ListSubAgents")
				.description(
					"List the configured Specter sub-agents that can be delegated specialized work.")
				.parameters(JsonObjectSchema.builder()
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("GetSubAgentDetails")
				.description(
					"Get the description and saved instructions for one configured Specter sub-agent by exact name.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("name", "Exact saved sub-agent name to inspect.")
						.required("name")
						.additionalProperties(false)
						.build())
				.build(),
		ToolSpecification.builder()
				.name("InvokeSubAgent")
				.description(
					"Invoke a configured Specter sub-agent by name. Provide the saved sub-agent name and a concrete delegated task.")
				.parameters(JsonObjectSchema.builder()
						.addStringProperty("name", "Exact saved sub-agent name to invoke.")
						.addStringProperty("task", "Delegated task for the sub-agent to complete.")
						.required("name", "task")
						.additionalProperties(false)
						.build())
				.build());
	private final List<ToolSpecification> toolSpecifications;

	SpecterCodeBrowserTools(SpecterPlugin plugin,
			SpecterSubAgentConfigurationManager subAgentConfigurationManager) {
		this.plugin = plugin;
		this.subAgentConfigurationManager = subAgentConfigurationManager;
		List<ToolSpecification> allToolSpecifications =
			new ArrayList<>(coreToolSpecifications.size() + subAgentToolSpecifications.size());
		allToolSpecifications.addAll(coreToolSpecifications);
		allToolSpecifications.addAll(subAgentToolSpecifications);
		toolSpecifications = List.copyOf(allToolSpecifications);
	}

	void setSubAgentExecutor(BiFunction<String, String, String> subAgentExecutor) {
		this.subAgentExecutor = subAgentExecutor == null ? this.subAgentExecutor : subAgentExecutor;
	}

	void setDslService(SpecterDslService dslService) {
		this.dslService = dslService;
	}

	SpecterToolHost coreToolHost() {
		return coreToolHost;
	}

	@Override
	public List<ToolSpecification> toolSpecifications() {
		return toolSpecifications;
	}

	@Override
	public Program currentProgram() {
		return plugin.getCurrentProgram();
	}

	@Override
	public String execute(ToolExecutionRequest request) {
		try {
			return limitResponseLength(switch (request.name()) {
				case "RunSpecterDslQuery" ->
					runSpecterDslQuery(readRequiredStringArgument(request, "query"));
				case "GetCurrentAddress" -> getCurrentAddress();
				case "SetListingComment" -> setListingComment(
					readRequiredStringArgument(request, "address"),
					readRequiredStringArgument(request, "comment_type"),
					readRequiredStringArgument(request, "text"));
				case "SetDecompilerComment" -> setDecompilerComment(
					readRequiredStringArgument(request, "address"),
					readRequiredStringArgument(request, "comment_type"),
					readRequiredStringArgument(request, "text"));
				case "RenameFunctionParameter" -> renameFunctionParameter(
					readRequiredStringArgument(request, "function_address"),
					readRequiredStringArgument(request, "current_name"),
					readRequiredStringArgument(request, "new_name"));
				case "RetypeFunctionParameter" -> retypeFunctionParameter(
					readRequiredStringArgument(request, "function_address"),
					readRequiredStringArgument(request, "current_name"),
					readRequiredStringArgument(request, "new_type"));
				case "RenameFunctionLocalVariable" -> renameFunctionLocalVariable(
					readRequiredStringArgument(request, "function_address"),
					readRequiredStringArgument(request, "current_name"),
					readRequiredStringArgument(request, "new_name"));
				case "CreateFunction" -> createFunction(
					readRequiredStringArgument(request, "address"),
					readOptionalStringArgument(request, "name"));
				case "RetypeGlobalData" -> retypeGlobalData(
					readRequiredStringArgument(request, "address"),
					readRequiredStringArgument(request, "new_type"));
				case "RetypeLocalVariable" -> retypeLocalVariable(
					readRequiredStringArgument(request, "function_address"),
					readRequiredStringArgument(request, "current_name"),
					readRequiredStringArgument(request, "new_type"));
				case "SearchDataTypesByNameRegex" ->
					searchDataTypesByNameRegex(readRequiredStringArgument(request, "regex"));
				case "GetDataTypeDetails" ->
					getDataTypeDetails(readRequiredStringArgument(request, "name_or_path"));
				case "CreateStructureDataType" -> createStructureDataType(request);
				case "ModifyStructureDataType" -> modifyStructureDataType(request);
				case "ListSubAgents" -> listSubAgents();
				case "GetSubAgentDetails" ->
					getSubAgentDetails(readRequiredStringArgument(request, "name"));
				case "InvokeSubAgent" -> invokeSubAgent(
					readRequiredStringArgument(request, "name"),
					readRequiredStringArgument(request, "task"));
				default -> "Error: Unknown tool '" + request.name() + "'.";
			});
		}
		catch (RuntimeException e) {
			return "Error: " + formatError(e);
		}
	}

	private String runSpecterDslQuery(String query) {
		if (dslService == null) {
			throw new IllegalStateException("Specter DSL service is unavailable.");
		}
		return dslService.execute(query,
			changeSummary -> approveDatabaseEdit("RunSpecterDslQuery", changeSummary));
	}

	private String listSubAgents() {
		List<SpecterSubAgentDefinition> definitions = subAgentConfigurationManager.definitions();
		if (definitions.isEmpty()) {
			return "Sub-agent count: 0\n\nNo sub-agents are configured.";
		}

		StringBuilder builder = new StringBuilder();
		builder.append("Sub-agent count: ").append(definitions.size()).append('\n');
		builder.append("\nSub-agents:\n");
		for (SpecterSubAgentDefinition definition : definitions) {
			builder.append("- ").append(definition.name());
			if (definition.description() != null) {
				builder.append(" | description=").append(definition.description());
			}
			builder.append('\n');
		}
		return builder.toString();
	}

	private String getSubAgentDetails(String subAgentName) {
		SpecterSubAgentDefinition definition =
			subAgentConfigurationManager.findByName(subAgentName);
		if (definition == null) {
			throw new IllegalStateException("Unknown sub-agent '" + subAgentName + "'.");
		}

		StringBuilder builder = new StringBuilder();
		builder.append("Sub-agent: ").append(definition.name()).append('\n');
		if (definition.description() != null) {
			builder.append("Description: ").append(definition.description()).append('\n');
		}
		builder.append("\nInstructions:\n").append(definition.instructions());
		return builder.toString();
	}

	private String invokeSubAgent(String subAgentName, String task) {
		return subAgentExecutor.apply(subAgentName, task);
	}

	private String getCurrentAddress() {
		ProgramLocation location = plugin.getProgramLocation();
		if (location == null || location.getAddress() == null) {
			throw new IllegalStateException(
				"No current code browser location is available. Open a program and place the cursor on an address.");
		}
		return location.getAddress().toString();
	}

	private String retypeGlobalData(String addressText, String newTypeText) {
		Program program = requireCurrentProgram();
		Address originalAddress = resolveAddress(program, addressText);
		Data existingData = program.getListing().getDefinedDataContaining(originalAddress);
		Address applyAddress = existingData == null ? originalAddress : existingData.getMinAddress();
		String oldTypeName = existingData == null ? "<undefined>" : existingData.getDataType().getPathName();

		approveDatabaseEdit("RetypeGlobalData",
			"Retype global data at " + applyAddress + " from '" + oldTypeName + "' to '" +
				newTypeText + "'.");
		return runWithTransaction(program, "Retype global data at " + applyAddress, () -> {
			DataType newDataType = resolveDataType(program, newTypeText);
			CreateDataCmd command = new CreateDataCmd(applyAddress, newDataType, false,
				DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			if (!command.applyTo(program)) {
				throw new IllegalStateException(statusOrDefault(command.getStatusMsg(),
					"Unable to apply datatype " + newDataType.getPathName() + " at " + applyAddress + "."));
			}
			return "Retyped global data at " + applyAddress + " from '" + oldTypeName + "' to '" +
				newDataType.getPathName() + "'.";
		});
	}

	private String retypeLocalVariable(String functionAddressText, String currentName, String newTypeText) {
		Program program = requireCurrentProgram();
		Address address = resolveAddress(program, functionAddressText);
		Function function = requireFunctionContaining(program, address);
		ensureLocalRenameTargetExists(function, currentName);

		approveDatabaseEdit("RetypeLocalVariable",
			"Retype local variable '" + currentName + "' in function " + function.getName() + " at " +
				function.getEntryPoint() + " to '" + newTypeText + "'.");
		return runWithTransaction(program, "Retype local variable in " + function.getEntryPoint(),
			() -> {
				DataType newDataType = resolveDataType(program, newTypeText);
				HighSymbol localSymbol = findLocalRenameTarget(program, function, currentName);
				if (localSymbol != null) {
					HighFunctionDBUtil.updateDBVariable(localSymbol, localSymbol.getName(), newDataType,
						EDIT_SOURCE_TYPE);
					return "Retyped local variable '" + currentName + "' in function " + function.getName() +
						" to '" + newDataType.getPathName() + "'.";
				}

				Variable localVariable = findUniqueLocalVariable(function, currentName);
				localVariable.setDataType(newDataType, EDIT_SOURCE_TYPE);
				return "Retyped local variable '" + currentName + "' in function " + function.getName() +
					" to '" + newDataType.getPathName() + "'.";
			});
	}

	private String searchDataTypesByNameRegex(String regexText) {
		Program program = requireCurrentProgram();
		Pattern pattern = compilePattern(regexText, "datatype names");
		List<DataType> matches = new ArrayList<>();
		int totalMatches = 0;

		for (DataType dataType : collectResolvableDataTypes(program)) {
			if (!pattern.matcher(dataType.getName()).find()) {
				continue;
			}
			totalMatches++;
			if (matches.size() < MAX_DATA_TYPE_SEARCH_RESULTS) {
				matches.add(dataType);
			}
		}

		StringBuilder builder = new StringBuilder();
		builder.append("Regex: ").append(regexText).append('\n');
		builder.append("Match Count: ").append(totalMatches).append('\n');
		if (totalMatches == 0) {
			builder.append("\nNo datatypes matched.");
			return builder.toString();
		}

		builder.append("\nMatches:\n");
		for (DataType dataType : matches) {
			builder.append("- ").append(dataType.getPathName());
			builder.append(" | kind=").append(describeDataTypeKind(dataType));
			builder.append(" | length=").append(formatDataTypeLength(dataType));
			builder.append('\n');
		}
		if (totalMatches > matches.size()) {
			builder.append("... ").append(totalMatches - matches.size())
					.append(" additional matches omitted.\n");
		}
		return builder.toString();
	}

	private String getDataTypeDetails(String nameOrPath) {
		Program program = requireCurrentProgram();
		DataType dataType = requireDataType(program, nameOrPath);
		StringBuilder builder = new StringBuilder();
		builder.append("Name: ").append(dataType.getName()).append('\n');
		builder.append("Path: ").append(dataType.getPathName()).append('\n');
		builder.append("Kind: ").append(describeDataTypeKind(dataType)).append('\n');
		builder.append("Length: ").append(formatDataTypeLength(dataType)).append('\n');
		String description = dataType.getDescription();
		if (description != null && !description.isBlank()) {
			builder.append("Description: ").append(description).append('\n');
		}

		if (dataType instanceof Structure structure) {
			builder.append("Defined Field Count: ").append(structure.getNumDefinedComponents()).append('\n');
			if (structure.getNumDefinedComponents() == 0) {
				builder.append("\nNo defined fields.");
				return builder.toString();
			}
			builder.append("\nFields:\n");
			for (DataTypeComponent component : structure.getDefinedComponents()) {
				builder.append("- offset=0x").append(Integer.toHexString(component.getOffset()));
				builder.append(" | name=").append(component.getFieldName());
				builder.append(" | type=").append(component.getDataType().getPathName());
				builder.append(" | length=").append(component.getLength());
				String comment = component.getComment();
				if (comment != null && !comment.isBlank()) {
					builder.append(" | comment=").append(comment.replace('\n', ' '));
				}
				builder.append('\n');
			}
		}

		return builder.toString();
	}

	private String createStructureDataType(ToolExecutionRequest request) {
		Program program = requireCurrentProgram();
		Map<?, ?> arguments = parseArguments(request.arguments());
		String name = requireStringValue(arguments, "name", request.name());
		String categoryPathText = optionalStringValue(arguments.get("category_path"));
		String description = optionalStringValue(arguments.get("description"));
		List<StructureFieldSpec> fields = readStructureFields(arguments.get("fields"), request.name());
		CategoryPath categoryPath = parseCategoryPath(categoryPathText);

		StringBuilder summary = new StringBuilder();
		summary.append("Create structure datatype '").append(name).append("' in category ")
				.append(categoryPath.getPath()).append(" with ").append(fields.size()).append(" field(s).");
		approveDatabaseEdit("CreateStructureDataType", summary.toString());

		return runWithTransaction(program, "Create structure datatype " + name, () -> {
			DataTypeManager dataTypeManager = program.getDataTypeManager();
			if (dataTypeManager.getDataType(categoryPath, name) != null) {
				throw new IllegalStateException(
					"Datatype already exists at " + new CategoryPath(categoryPath, name).getPath() + ".");
			}

			StructureDataType structure = new StructureDataType(categoryPath, name, 0, dataTypeManager);
			if (description != null) {
				structure.setDescription(description);
			}
			for (StructureFieldSpec field : fields) {
				DataType fieldType = resolveDataType(program, field.typeExpression());
				structure.add(fieldType, field.name(), field.comment());
			}

			DataType addedDataType =
				dataTypeManager.addDataType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
			return "Created structure datatype '" + addedDataType.getPathName() + "' with " +
				fields.size() + " field(s).";
		});
	}

	private String modifyStructureDataType(ToolExecutionRequest request) {
		Program program = requireCurrentProgram();
		Map<?, ?> arguments = parseArguments(request.arguments());
		String nameOrPath = requireStringValue(arguments, "name_or_path", request.name());
		String description = optionalStringValue(arguments.get("description"));
		boolean replaceFields = readOptionalBooleanValue(arguments.get("replace_fields"));
		List<StructureFieldSpec> fields = readOptionalStructureFields(arguments.get("fields"), request.name());

		DataType dataType = requireDataType(program, nameOrPath);
		if (!(dataType instanceof Structure structure)) {
			throw new IllegalStateException(
				"Datatype '" + dataType.getPathName() + "' is not a structure and cannot be modified.");
		}

		if (description == null && fields.isEmpty()) {
			throw new IllegalArgumentException(
				"ModifyStructureDataType requires a description change, field changes, or both.");
		}

		StringBuilder summary = new StringBuilder();
		summary.append("Modify structure datatype '").append(structure.getPathName()).append("'.");
		if (description != null) {
			summary.append("\n\nUpdate description.");
		}
		if (!fields.isEmpty()) {
			summary.append("\n\n");
			summary.append(replaceFields ? "Replace all fields with " : "Append ");
			summary.append(fields.size()).append(" field(s).");
		}
		approveDatabaseEdit("ModifyStructureDataType", summary.toString());

		return runWithTransaction(program, "Modify structure datatype " + structure.getPathName(), () -> {
			Structure targetStructure = requireStructureDataType(program, nameOrPath);
			if (description != null) {
				targetStructure.setDescription(description);
			}
			if (!fields.isEmpty()) {
				if (replaceFields) {
					targetStructure.deleteAll();
				}
				for (StructureFieldSpec field : fields) {
					DataType fieldType = resolveDataType(program, field.typeExpression());
					targetStructure.add(fieldType, field.name(), field.comment());
				}
			}

			StringBuilder result = new StringBuilder();
			result.append("Modified structure datatype '").append(targetStructure.getPathName()).append("'.");
			if (description != null) {
				result.append(" Updated description.");
			}
			if (!fields.isEmpty()) {
				result.append(' ');
				result.append(replaceFields ? "Replaced fields with " : "Appended ");
				result.append(fields.size()).append(" field(s).");
			}
			return result.toString();
		});
	}

	private String setListingComment(String addressText, String commentTypeText, String commentText) {
		Program program = requireCurrentProgram();
		Address address = resolveAddress(program, addressText);
		CommentType commentType = parseListingCommentType(commentTypeText);
		String normalizedCommentText = normalizeCommentText(commentText);
		approveDatabaseEdit("SetListingComment",
			"Set " + commentType.name().toLowerCase() + " listing comment at " + address + " to:\n\n" +
				normalizedCommentText);
		return runWithTransaction(program, "Set listing comment at " + address, () -> {
			SetCommentCmd command = new SetCommentCmd(address, commentType, normalizedCommentText);
			if (!command.applyTo(program)) {
				throw new IllegalStateException(statusOrDefault(command.getStatusMsg(),
					"Unable to set listing comment at " + address + "."));
			}
			return "Stored " + commentType.name().toLowerCase() + " listing comment at " + address + ".";
		});
	}

	private String setDecompilerComment(String addressText, String commentTypeText, String commentText) {
		Program program = requireCurrentProgram();
		Address address = resolveAddress(program, addressText);
		CommentType commentType = parseDecompilerCommentType(commentTypeText);
		String normalizedCommentText = normalizeCommentText(commentText);
		approveDatabaseEdit("SetDecompilerComment",
			"Set " + commentType.name().toLowerCase() + " decompiler comment at " + address +
				" to:\n\n" + normalizedCommentText);
		return runWithTransaction(program, "Set decompiler comment at " + address, () -> {
			SetCommentCmd command = new SetCommentCmd(address, commentType, normalizedCommentText);
			if (!command.applyTo(program)) {
				throw new IllegalStateException(statusOrDefault(command.getStatusMsg(),
					"Unable to set decompiler comment at " + address + "."));
			}
			return "Stored " + commentType.name().toLowerCase() +
				" decompiler comment at " + address + ".";
		});
	}

	private String renameFunctionParameter(String functionAddressText, String currentName,
			String newName) {
		Program program = requireCurrentProgram();
		Address address = resolveAddress(program, functionAddressText);
		Function function = requireFunctionContaining(program, address);
		ensureParameterRenameTargetExists(function, currentName);
		approveDatabaseEdit("RenameFunctionParameter",
			"Rename parameter '" + currentName + "' to '" + newName + "' in function " +
				function.getName() + " at " + function.getEntryPoint() + ".");
		return runWithTransaction(program, "Rename parameter in " + function.getEntryPoint(), () -> {
			HighSymbol parameterSymbol = findParameterRenameTarget(program, function, currentName);
			if (parameterSymbol != null) {
				HighFunctionDBUtil.updateDBVariable(parameterSymbol, newName,
					parameterSymbol.getDataType(), EDIT_SOURCE_TYPE);
				return "Renamed parameter in " + function.getName() + " from '" + currentName +
					"' to '" + newName + "'.";
			}

			Parameter parameter = findUniqueParameter(function, currentName);
			parameter.setName(newName, EDIT_SOURCE_TYPE);
				return "Renamed parameter in " + function.getName() + " from '" + currentName +
					"' to '" + newName + "'.";
			});
	}

	private String retypeFunctionParameter(String functionAddressText, String currentName,
			String newTypeText) {
		Program program = requireCurrentProgram();
		Address address = resolveAddress(program, functionAddressText);
		Function function = requireFunctionContaining(program, address);
		ensureParameterRenameTargetExists(function, currentName);

		approveDatabaseEdit("RetypeFunctionParameter",
			"Retype parameter '" + currentName + "' in function " + function.getName() + " at " +
				function.getEntryPoint() + " to '" + newTypeText + "'.");
		return runWithTransaction(program, "Retype parameter in " + function.getEntryPoint(), () -> {
			DataType newDataType = resolveDataType(program, newTypeText);
			HighSymbol parameterSymbol = findParameterRenameTarget(program, function, currentName);
			if (parameterSymbol != null) {
				HighFunctionDBUtil.updateDBVariable(parameterSymbol, parameterSymbol.getName(), newDataType,
					EDIT_SOURCE_TYPE);
				return "Retyped parameter '" + currentName + "' in function " + function.getName() +
					" to '" + newDataType.getPathName() + "'.";
			}

			Parameter parameter = findUniqueParameter(function, currentName);
			parameter.setDataType(newDataType, EDIT_SOURCE_TYPE);
			return "Retyped parameter '" + currentName + "' in function " + function.getName() +
				" to '" + newDataType.getPathName() + "'.";
		});
	}

	private String renameFunctionLocalVariable(String functionAddressText, String currentName,
			String newName) {
		Program program = requireCurrentProgram();
		Address address = resolveAddress(program, functionAddressText);
		Function function = requireFunctionContaining(program, address);
		ensureLocalRenameTargetExists(function, currentName);
		approveDatabaseEdit("RenameFunctionLocalVariable",
			"Rename local variable '" + currentName + "' to '" + newName + "' in function " +
				function.getName() + " at " + function.getEntryPoint() + ".");
		return runWithTransaction(program, "Rename local variable in " + function.getEntryPoint(),
				() -> {
					HighSymbol localSymbol = findLocalRenameTarget(program, function, currentName);
					if (localSymbol != null) {
						HighFunctionDBUtil.updateDBVariable(localSymbol, newName,
							localSymbol.getDataType(), EDIT_SOURCE_TYPE);
					return "Renamed local variable in " + function.getName() + " from '" +
						currentName + "' to '" + newName + "'.";
				}

				Variable localVariable = findUniqueLocalVariable(function, currentName);
				localVariable.setName(newName, EDIT_SOURCE_TYPE);
				return "Renamed local variable in " + function.getName() + " from '" +
					currentName + "' to '" + newName + "'.";
			});
	}

	private String createFunction(String addressText, String functionName) {
		Program program = requireCurrentProgram();
		Address address = resolveAddress(program, addressText);

		Function existingFunction = program.getFunctionManager().getFunctionAt(address);
		if (existingFunction != null) {
			return "Function already exists at " + address + ": " + existingFunction.getName() + ".";
		}

		Function containingFunction = program.getFunctionManager().getFunctionContaining(address);
		if (containingFunction != null) {
			throw new IllegalStateException("Address " + address + " is already inside function " +
				containingFunction.getName() + " at " + containingFunction.getEntryPoint() + ".");
		}

		StringBuilder summary = new StringBuilder();
		summary.append("Create a function at ").append(address).append('.');
		if (functionName != null) {
			summary.append("\n\nRequested name: ").append(functionName);
		}
		approveDatabaseEdit("CreateFunction", summary.toString());

		return runWithTransaction(program, "Create function at " + address, () -> {
			CreateFunctionCmd command = new CreateFunctionCmd(functionName, address, null, EDIT_SOURCE_TYPE);
			if (!command.applyTo(program, TaskMonitor.DUMMY)) {
				throw new IllegalStateException(
					statusOrDefault(command.getStatusMsg(), "Unable to create function at " + address + "."));
			}

			Function createdFunction = command.getFunction();
			if (createdFunction == null) {
				createdFunction = program.getFunctionManager().getFunctionAt(address);
			}
			if (createdFunction == null) {
				throw new IllegalStateException("Function creation reported success but no function exists at " +
					address + ".");
			}
			return "Created function " + createdFunction.getName() + " at " +
				createdFunction.getEntryPoint() + ".";
		});
	}

	private Program requireCurrentProgram() {
		Program program = plugin.getCurrentProgram();
		if (program == null) {
			throw new IllegalStateException("No current program is open in Ghidra.");
		}
		return program;
	}

	private Function requireFunctionContaining(Program program, Address address) {
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			throw new IllegalStateException("No function contains address " + address + ".");
		}
		return function;
	}

	private DecompileResults decompileFunction(Program program, Function function) {
		DecompInterface decompiler = new DecompInterface();
		try {
			if (!decompiler.openProgram(program)) {
				throw new IllegalStateException("Unable to open the current program in the decompiler.");
			}

			DecompileResults results =
				decompiler.decompileFunction(function, DECOMPILATION_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
			if (!results.decompileCompleted()) {
				throw new IllegalStateException(buildDecompilationFailureMessage(results, function));
			}
			return results;
		}
		finally {
			decompiler.dispose();
		}
	}

	private HighFunction requireHighFunction(Program program, Function function) {
		DecompileResults results = decompileFunction(program, function);
		HighFunction highFunction = results.getHighFunction();
		if (highFunction == null) {
			throw new IllegalStateException(
				"Decompiler returned no high function for " + function.getName() + ".");
		}
		return highFunction;
	}

	private HighSymbol findParameterRenameTarget(Program program, Function function, String currentName) {
		HighFunction highFunction = requireHighFunction(program, function);
		return findUniqueHighSymbol(highFunction, currentName,
			symbol -> symbol.isParameter() && !symbol.isThisPointer() && !symbol.isHiddenReturn(),
			"parameter");
	}

	private HighSymbol findLocalRenameTarget(Program program, Function function, String currentName) {
		HighFunction highFunction = requireHighFunction(program, function);
		return findUniqueHighSymbol(highFunction, currentName,
			symbol -> !symbol.isParameter() && !symbol.isGlobal(), "local variable");
	}

	private void ensureParameterRenameTargetExists(Function function, String currentName) {
		HighSymbol parameterSymbol = findParameterRenameTarget(function.getProgram(), function, currentName);
		if (parameterSymbol == null) {
			findUniqueParameter(function, currentName);
		}
	}

	private void ensureLocalRenameTargetExists(Function function, String currentName) {
		HighSymbol localSymbol = findLocalRenameTarget(function.getProgram(), function, currentName);
		if (localSymbol == null) {
			findUniqueLocalVariable(function, currentName);
		}
	}

	private CommentType parseListingCommentType(String commentTypeText) {
		return switch (normalizeCommentType(commentTypeText)) {
			case "EOL", "END_OF_LINE" -> CommentType.EOL;
			case "PRE" -> CommentType.PRE;
			case "POST" -> CommentType.POST;
			case "PLATE" -> CommentType.PLATE;
			case "REPEATABLE" -> CommentType.REPEATABLE;
			default -> throw new IllegalArgumentException(
				"Unsupported listing comment type '" + commentTypeText +
					"'. Use eol, pre, post, plate, or repeatable.");
		};
	}

	private CommentType parseDecompilerCommentType(String commentTypeText) {
		return switch (normalizeCommentType(commentTypeText)) {
			case "PRE" -> CommentType.PRE;
			case "PLATE" -> CommentType.PLATE;
			default -> throw new IllegalArgumentException(
				"Unsupported decompiler comment type '" + commentTypeText +
					"'. Use pre or plate.");
		};
	}

	private String normalizeCommentType(String commentTypeText) {
		return commentTypeText.trim().replace('-', '_').replace(' ', '_').toUpperCase();
	}

	private String normalizeCommentText(String commentText) {
		String normalized = commentText.trim();
		if (normalized.startsWith("/*")) {
			normalized = normalized.substring(2).trim();
		}
		if (normalized.endsWith("*/")) {
			normalized = normalized.substring(0, normalized.length() - 2).trim();
		}
		return normalized;
	}

	private Parameter findUniqueParameter(Function function, String name) {
		List<Parameter> matches = new ArrayList<>();
		for (Parameter parameter : function.getParameters()) {
			if (parameter.isAutoParameter()) {
				continue;
			}
			if (name.equals(parameter.getName())) {
				matches.add(parameter);
			}
		}
		if (matches.isEmpty()) {
			throw new IllegalStateException(
				"No parameter named '" + name + "' exists in function " + function.getName() + ".");
		}
		if (matches.size() > 1) {
			throw new IllegalStateException(
				"Multiple parameters named '" + name + "' exist in function " + function.getName() + ".");
		}
		return matches.get(0);
	}

	private Variable findUniqueLocalVariable(Function function, String name) {
		List<Variable> matches = new ArrayList<>();
		for (Variable variable : function.getLocalVariables()) {
			if (name.equals(variable.getName())) {
				matches.add(variable);
			}
		}
		if (matches.isEmpty()) {
			throw new IllegalStateException(
				"No local variable named '" + name + "' exists in function " + function.getName() + ".");
		}
		if (matches.size() > 1) {
			throw new IllegalStateException(
				"Multiple local variables named '" + name + "' exist in function " + function.getName() + ".");
		}
		return matches.get(0);
	}

	private HighSymbol findUniqueHighSymbol(HighFunction highFunction, String name,
			Predicate<HighSymbol> predicate, String symbolTypeLabel) {
		List<HighSymbol> matches = new ArrayList<>();
		for (HighSymbol symbol : collectHighSymbols(highFunction)) {
			if (!predicate.test(symbol)) {
				continue;
			}
			if (name.equals(symbol.getName())) {
				matches.add(symbol);
			}
		}

		if (matches.isEmpty()) {
			return null;
		}
		if (matches.size() > 1) {
			String functionName = highFunction.getFunction().getName();
			throw new IllegalStateException("Multiple " + symbolTypeLabel + "s named '" + name +
				"' exist in function " + functionName + ". Rename is ambiguous.");
		}
		return matches.get(0);
	}

	private List<HighSymbol> collectHighSymbols(HighFunction highFunction) {
		List<HighSymbol> symbols = new ArrayList<>();
		var iterator = highFunction.getLocalSymbolMap().getSymbols();
		while (iterator.hasNext()) {
			HighSymbol symbol = iterator.next();
			if (symbol != null && symbol.getName() != null && !symbol.getName().isBlank()) {
				symbols.add(symbol);
			}
		}
		return symbols;
	}

	private String runWithTransaction(Program program, String description, WriteOperation operation) {
		int transactionId = program.startTransaction(description);
		boolean commit = false;
		try {
			String result = operation.run();
			commit = true;
			return result;
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IllegalStateException(formatError(e), e);
		}
		finally {
			program.endTransaction(transactionId, commit);
		}
	}

	private void approveDatabaseEdit(String toolName, String changeSummary) {
		if (databaseEditPreferences.alwaysAllow(toolName)) {
			return;
		}

		SpecterDatabaseEditApprovalDialog.Result result = SystemUtilities.runSwingNow(
			() -> SpecterDatabaseEditApprovalDialog.showDialog(plugin.dialogParent(), toolName,
				changeSummary));
		if (!result.approved()) {
			throw new IllegalStateException(
				"User denied permission for tool '" + toolName + "'. No database changes were made.");
		}
		if (result.alwaysAllowFutureRuns()) {
			databaseEditPreferences.setAlwaysAllow(toolName, true);
		}
	}

	private String readRequiredStringArgument(ToolExecutionRequest request, String name) {
		Map<?, ?> arguments = parseArguments(request.arguments());
		Object value = arguments.get(name);
		if (value instanceof String text && !text.isBlank()) {
			return text.trim();
		}
		throw new IllegalArgumentException(
			"Tool '" + request.name() + "' requires a non-empty string argument named '" + name + "'.");
	}

	private String readOptionalStringArgument(ToolExecutionRequest request, String name) {
		Map<?, ?> arguments = parseArguments(request.arguments());
		Object value = arguments.get(name);
		if (!(value instanceof String text)) {
			return null;
		}
		String trimmed = text.trim();
		return trimmed.isEmpty() ? null : trimmed;
	}

	private String requireStringValue(Map<?, ?> arguments, String name, String toolName) {
		Object value = arguments.get(name);
		if (value instanceof String text && !text.isBlank()) {
			return text.trim();
		}
		throw new IllegalArgumentException(
			"Tool '" + toolName + "' requires a non-empty string argument named '" + name + "'.");
	}

	private String optionalStringValue(Object value) {
		if (!(value instanceof String text)) {
			return null;
		}
		String trimmed = text.trim();
		return trimmed.isEmpty() ? null : trimmed;
	}

	private List<StructureFieldSpec> readStructureFields(Object value, String toolName) {
		if (!(value instanceof List<?> list) || list.isEmpty()) {
			throw new IllegalArgumentException(
				"Tool '" + toolName + "' requires a non-empty array argument named 'fields'.");
		}

		List<StructureFieldSpec> fields = new ArrayList<>();
		for (int i = 0; i < list.size(); i++) {
			Object item = list.get(i);
			if (!(item instanceof Map<?, ?> fieldMap)) {
				throw new IllegalArgumentException(
					"Each entry in 'fields' for tool '" + toolName + "' must be an object.");
			}
			String fieldName = requireStringValue(fieldMap, "name", toolName);
			String typeExpression = requireStringValue(fieldMap, "type", toolName);
			String comment = optionalStringValue(fieldMap.get("comment"));
			fields.add(new StructureFieldSpec(fieldName, typeExpression, comment));
		}
		return fields;
	}

	private List<StructureFieldSpec> readOptionalStructureFields(Object value, String toolName) {
		if (value == null) {
			return List.of();
		}
		return readStructureFields(value, toolName);
	}

	private boolean readOptionalBooleanValue(Object value) {
		return value instanceof Boolean booleanValue ? booleanValue.booleanValue() : false;
	}

	private Map<?, ?> parseArguments(String argumentsJson) {
		if (argumentsJson == null || argumentsJson.isBlank()) {
			return Map.of();
		}

		Object parsed = Json.fromJson(argumentsJson, Map.class);
		if (parsed instanceof Map<?, ?> map) {
			return map;
		}
		throw new IllegalArgumentException("Tool arguments must be a JSON object.");
	}

	private Address resolveAddress(Program program, String addressText) {
		Address[] parsedAddresses = program.parseAddress(addressText);
		if (parsedAddresses != null && parsedAddresses.length > 0 && parsedAddresses[0] != null) {
			return parsedAddresses[0];
		}

		String normalized = addressText.trim();
		if (normalized.startsWith("0x") || normalized.startsWith("0X")) {
			normalized = normalized.substring(2);
		}

		Address address = program.getAddressFactory().getAddress(normalized);
		if (address != null) {
			return address;
		}

		throw new IllegalArgumentException(
			"Unable to parse address '" + addressText + "' in the current program.");
	}

	private DataType resolveDataType(Program program, String typeExpression) {
		DataTypeManager programDataTypeManager = program.getDataTypeManager();
		DataTypeParser parser = new DataTypeParser(programDataTypeManager,
			BuiltInDataTypeManager.getDataTypeManager(), null, DataTypeParser.AllowedDataTypes.ALL);
		try {
			DataType dataType = parser.parse(typeExpression, CategoryPath.ROOT);
			return programDataTypeManager.resolve(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		catch (InvalidDataTypeException e) {
			try {
				return resolveDataTypeFallback(program, typeExpression);
			}
			catch (IllegalArgumentException fallbackError) {
				throw new IllegalArgumentException(
					"Unable to parse datatype expression '" + typeExpression + "': " + e.getMessage() + ". " +
						fallbackError.getMessage());
			}
		}
		catch (CancelledException e) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Datatype parsing was cancelled.", e);
		}
	}

	private DataType resolveDataTypeFallback(Program program, String typeExpression) {
		String remaining = typeExpression.trim();
		if (remaining.isEmpty()) {
			throw new IllegalArgumentException("Datatype expression is empty.");
		}

		List<Integer> strippedArrayDimensions = new ArrayList<>();
		while (remaining.endsWith("]")) {
			int openBracket = remaining.lastIndexOf('[');
			if (openBracket < 0) {
				throw new IllegalArgumentException(
					"Malformed array datatype expression '" + typeExpression + "'.");
			}
			String dimensionText = remaining.substring(openBracket + 1, remaining.length() - 1).trim();
			if (dimensionText.isEmpty()) {
				throw new IllegalArgumentException(
					"Array datatype expression '" + typeExpression + "' is missing a dimension size.");
			}
			int dimension;
			try {
				dimension = Integer.parseInt(dimensionText);
			}
			catch (NumberFormatException e) {
				throw new IllegalArgumentException(
					"Array datatype expression '" + typeExpression + "' has invalid dimension '" +
						dimensionText + "'.");
			}
			if (dimension <= 0) {
				throw new IllegalArgumentException(
					"Array datatype expression '" + typeExpression + "' must use positive dimensions.");
			}
			strippedArrayDimensions.add(dimension);
			remaining = remaining.substring(0, openBracket).trim();
		}

		int pointerDepth = 0;
		while (remaining.endsWith("*")) {
			pointerDepth++;
			remaining = remaining.substring(0, remaining.length() - 1).trim();
		}
		if (remaining.isEmpty()) {
			throw new IllegalArgumentException(
				"Datatype expression '" + typeExpression + "' is missing a base datatype.");
		}

		DataTypeManager programDataTypeManager = program.getDataTypeManager();
		DataType dataType = requireDataType(program, remaining);
		dataType = programDataTypeManager.resolve(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);

		for (int i = 0; i < pointerDepth; i++) {
			dataType = programDataTypeManager.getPointer(dataType);
		}
		for (int i = strippedArrayDimensions.size() - 1; i >= 0; i--) {
			int dimension = strippedArrayDimensions.get(i);
			dataType = new ghidra.program.model.data.ArrayDataType(dataType, dimension, dataType.getLength(),
				programDataTypeManager);
		}
		return programDataTypeManager.resolve(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private DataType requireDataType(Program program, String nameOrPath) {
		DataType exact = findDataType(program, nameOrPath);
		if (exact != null) {
			return exact;
		}
		List<DataType> matches = new ArrayList<>();
		for (DataType dataType : collectResolvableDataTypes(program)) {
			if (nameOrPath.equals(dataType.getName()) || nameOrPath.equals(dataType.getPathName())) {
				matches.add(dataType);
			}
		}
		if (matches.isEmpty()) {
			throw new IllegalStateException("No datatype named '" + nameOrPath + "' exists.");
		}
		if (matches.size() > 1) {
			throw new IllegalStateException(
				"Datatype name '" + nameOrPath + "' is ambiguous. Use the full datatype path.");
		}
		return matches.get(0);
	}

	private Structure requireStructureDataType(Program program, String nameOrPath) {
		DataType dataType = requireDataType(program, nameOrPath);
		if (dataType instanceof Structure structure) {
			return structure;
		}
		throw new IllegalStateException(
			"Datatype '" + dataType.getPathName() + "' is not a structure.");
	}

	private DataType findDataType(Program program, String nameOrPath) {
		DataTypeManager programManager = program.getDataTypeManager();
		if (nameOrPath.startsWith("/")) {
			int slashIndex = nameOrPath.lastIndexOf('/');
			if (slashIndex >= 0 && slashIndex < nameOrPath.length() - 1) {
				CategoryPath categoryPath =
					slashIndex == 0 ? CategoryPath.ROOT : new CategoryPath(nameOrPath.substring(0, slashIndex));
				String name = nameOrPath.substring(slashIndex + 1);
				DataType dataType = programManager.getDataType(categoryPath, name);
				if (dataType != null) {
					return dataType;
				}
				return BuiltInDataTypeManager.getDataTypeManager().getDataType(categoryPath, name);
			}
		}

		DataType dataType = programManager.findDataType(nameOrPath);
		if (dataType != null) {
			return dataType;
		}
		return BuiltInDataTypeManager.getDataTypeManager().findDataType(nameOrPath);
	}

	private List<DataType> collectResolvableDataTypes(Program program) {
		List<DataType> dataTypes = new ArrayList<>();
		addAllDataTypes(program.getDataTypeManager(), dataTypes);
		addAllDataTypes(BuiltInDataTypeManager.getDataTypeManager(), dataTypes);
		return dataTypes;
	}

	private void addAllDataTypes(DataTypeManager dataTypeManager, List<DataType> dataTypes) {
		var iterator = dataTypeManager.getAllDataTypes();
		while (iterator.hasNext()) {
			DataType dataType = iterator.next();
			if (dataType == null || dataType.getName() == null) {
				continue;
			}
			if (isDuplicateDataType(dataTypes, dataType)) {
				continue;
			}
			dataTypes.add(dataType);
		}
	}

	private boolean isDuplicateDataType(List<DataType> existing, DataType candidate) {
		for (DataType existingType : existing) {
			if (existingType.getPathName().equals(candidate.getPathName())) {
				return true;
			}
		}
		return false;
	}

	private CategoryPath parseCategoryPath(String categoryPathText) {
		if (categoryPathText == null || categoryPathText.isBlank() || "/".equals(categoryPathText.trim())) {
			return CategoryPath.ROOT;
		}
		return new CategoryPath(categoryPathText.trim());
	}

	private String describeDataTypeKind(DataType dataType) {
		if (dataType instanceof Structure) {
			return "structure";
		}
		String simpleName = dataType.getClass().getSimpleName();
		if (simpleName.endsWith("DataType")) {
			simpleName = simpleName.substring(0, simpleName.length() - "DataType".length());
		}
		return simpleName.isEmpty() ? "datatype" : simpleName.toLowerCase();
	}

	private String formatDataTypeLength(DataType dataType) {
		return dataType.hasLanguageDependantLength() ? "dynamic" : String.valueOf(dataType.getLength());
	}

	private Pattern compilePattern(String regexText, String subject) {
		try {
			return Pattern.compile(regexText);
		}
		catch (PatternSyntaxException e) {
			throw new IllegalArgumentException(
				"Invalid regex for " + subject + " '" + regexText + "': " + e.getDescription() + ".");
		}
	}

	private String describeDataValue(Data data) {
		Object value = data.getValue();
		if (value == null) {
			return "<null>";
		}
		String text = String.valueOf(value).replace('\n', ' ').trim();
		if (text.isEmpty()) {
			return "<empty>";
		}
		if (text.length() <= 120) {
			return text;
		}
		return text.substring(0, 120) + "...";
	}

	private String buildDecompilationFailureMessage(DecompileResults results, Function function) {
		if (results == null) {
			return "Decompiler returned no results for function " + function.getName() + ".";
		}
		if (results.isTimedOut()) {
			return "Decompiler timed out while processing function " + function.getName() + ".";
		}
		if (results.isCancelled()) {
			return "Decompiler was cancelled while processing function " + function.getName() + ".";
		}
		if (results.failedToStart()) {
			return "Decompiler failed to start for function " + function.getName() + ".";
		}
		String errorMessage = results.getErrorMessage();
		if (errorMessage != null && !errorMessage.isBlank()) {
			return errorMessage;
		}
		return "Decompiler did not complete for function " + function.getName() + ".";
	}

	private String statusOrDefault(String statusMessage, String defaultMessage) {
		return statusMessage == null || statusMessage.isBlank() ? defaultMessage : statusMessage;
	}

	private String limitResponseLength(String value) {
		if (value.length() <= MAX_TOOL_RESPONSE_LENGTH) {
			return value;
		}
		return value.substring(0, MAX_TOOL_RESPONSE_LENGTH) +
			"\n\n[truncated by Specter after " + MAX_TOOL_RESPONSE_LENGTH + " characters]";
	}

	private String formatError(Throwable error) {
		String message = error.getMessage();
		return message == null || message.isBlank() ? error.getClass().getSimpleName() : message;
	}

	@FunctionalInterface
	private interface WriteOperation {
		String run() throws Exception;
	}

	private record StructureFieldSpec(String name, String typeExpression, String comment) {
	}
}
