package com.coldentry.specter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.AcyclicCallGraphBuilder;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.graph.AbstractDependencyGraph;
import ghidra.util.task.TaskMonitor;

final class SpecterSqlQueryService {

	private static final int DEFAULT_ROW_LIMIT = 200;
	private static final int DECOMPILATION_TIMEOUT_SECONDS = 30;
	private static final int MAX_ROW_LIMIT = 1_000;
	private static final int MAX_RENDERED_LENGTH = 32_000;
	private static final int MAX_CELL_WIDTH = 80;
	private static final String FUNCTION_TABLE = "FUNCTION";
	private static final String STRING_TABLE = "STRING";
	private static final String DATA_TABLE = "DATA";
	private static final String REFERENCE_TABLE = "REFERENCE";
	private static final String SYMBOL_TABLE = "SYMBOL";
	private static final String CALLGRAPH_LEVEL_FUNCTION = "callgraph_level";
	private static final String CONCAT_FUNCTION = "concat";
	private static final String COUNT_FUNCTION = "count";
	private static final String DECOMPILATION_FUNCTION = "decompilation";
	private static final String INSTRUCTIONS_FUNCTION = "instructions";
	private static final String PROMPT_FUNCTION = "prompt";
	private static final SourceType EDIT_SOURCE_TYPE = SourceType.AI;
	private static final int MAX_PROMPT_CONTEXT_VALUE_LENGTH = 400;

	private final Supplier<Program> programSupplier;
	private final SpecterPromptInvoker promptInvoker;

	private static final List<Column> FUNCTION_COLUMNS = List.of(
		new Column("entry", row -> ((FunctionRow) row).entry),
		new Column("name", row -> ((FunctionRow) row).name),
		new Column("namespace", row -> ((FunctionRow) row).namespace),
		new Column("signature", row -> ((FunctionRow) row).signature),
		new Column("return_type", row -> ((FunctionRow) row).returnType),
		new Column("parameter_count", row -> ((FunctionRow) row).parameterCount),
		new Column("body_min", row -> ((FunctionRow) row).bodyMin),
		new Column("body_max", row -> ((FunctionRow) row).bodyMax),
		new Column("body_size", row -> ((FunctionRow) row).bodySize),
		new Column("is_external", row -> ((FunctionRow) row).external),
		new Column("is_thunk", row -> ((FunctionRow) row).thunk),
		new Column("calling_convention", row -> ((FunctionRow) row).callingConvention),
		new Column("source", row -> ((FunctionRow) row).source));
	private static final List<Column> STRING_COLUMNS = List.of(
		new Column("address", row -> ((StringRow) row).address),
		new Column("value", row -> ((StringRow) row).value),
		new Column("data_type", row -> ((StringRow) row).dataType),
		new Column("length", row -> ((StringRow) row).length));
	private static final List<Column> DATA_COLUMNS = List.of(
		new Column("address", row -> ((DataRow) row).address),
		new Column("name", row -> ((DataRow) row).name),
		new Column("namespace", row -> ((DataRow) row).namespace),
		new Column("data_type", row -> ((DataRow) row).dataType),
		new Column("base_data_type", row -> ((DataRow) row).baseDataType),
		new Column("length", row -> ((DataRow) row).length),
		new Column("value", row -> ((DataRow) row).value),
		new Column("value_text", row -> ((DataRow) row).valueText),
		new Column("is_constant", row -> ((DataRow) row).constant),
		new Column("is_writable", row -> ((DataRow) row).writable),
		new Column("is_volatile", row -> ((DataRow) row).volatileData),
		new Column("is_pointer", row -> ((DataRow) row).pointer),
		new Column("is_array", row -> ((DataRow) row).array),
		new Column("is_string", row -> ((DataRow) row).string),
		new Column("is_global", row -> ((DataRow) row).global),
		new Column("containing_function", row -> ((DataRow) row).containingFunction),
		new Column("source", row -> ((DataRow) row).source),
		new Column("reference_count", row -> ((DataRow) row).referenceCount));
	private static final List<Column> REFERENCE_COLUMNS = List.of(
		new Column("from_address", row -> ((ReferenceRow) row).fromAddress),
		new Column("to_address", row -> ((ReferenceRow) row).toAddress),
		new Column("type", row -> ((ReferenceRow) row).type),
		new Column("source", row -> ((ReferenceRow) row).source));
	private static final List<Column> SYMBOL_COLUMNS = List.of(
		new Column("address", row -> ((SymbolRow) row).address),
		new Column("name", row -> ((SymbolRow) row).name),
		new Column("namespace", row -> ((SymbolRow) row).namespace),
		new Column("source", row -> ((SymbolRow) row).source));
	private static final TableSchema FUNCTION_SCHEMA = TableSchema.of(FUNCTION_TABLE, FUNCTION_COLUMNS);
	private static final TableSchema STRING_SCHEMA = TableSchema.of(STRING_TABLE, STRING_COLUMNS);
	private static final TableSchema DATA_SCHEMA = TableSchema.of(DATA_TABLE, DATA_COLUMNS);
	private static final TableSchema REFERENCE_SCHEMA =
		TableSchema.of(REFERENCE_TABLE, REFERENCE_COLUMNS);
	private static final TableSchema SYMBOL_SCHEMA = TableSchema.of(SYMBOL_TABLE, SYMBOL_COLUMNS);
	private static final Map<String, TableSchema> TABLES_BY_NAME = Map.of(
		FUNCTION_TABLE, FUNCTION_SCHEMA,
		STRING_TABLE, STRING_SCHEMA,
		DATA_TABLE, DATA_SCHEMA,
		REFERENCE_TABLE, REFERENCE_SCHEMA,
		SYMBOL_TABLE, SYMBOL_SCHEMA);

	SpecterSqlQueryService(Supplier<Program> programSupplier, SpecterPromptInvoker promptInvoker) {
		this.programSupplier = Objects.requireNonNull(programSupplier);
		this.promptInvoker = Objects.requireNonNull(promptInvoker);
	}

	String schemaHelp() {
		StringBuilder builder = new StringBuilder();
		builder.append("Usage: SELECT <expressions> [ORDER BY ...] [LIMIT ...]\n");
		builder.append("Usage: SELECT [UNIQUE|DISTINCT] <columns|*> FROM ")
				.append("<FUNCTION|STRING|DATA|REFERENCE|SYMBOL> [WHERE ...] ")
				.append("[GROUP BY ...] [ORDER BY ...] [LIMIT ...]\n");
		builder.append("       SELECT ... FROM <table> <alias> JOIN <table> <alias> ")
				.append("ON <condition> [WHERE ...]\n");
		builder.append("       UPDATE <FUNCTION|DATA|SYMBOL> SET name = <string expression> ")
				.append("WHERE ...\n");
		builder.append("\nFUNCTION columns:\n");
		for (Column column : FUNCTION_COLUMNS) {
			builder.append("  ").append(column.name()).append('\n');
		}
		builder.append("\nSTRING columns:\n");
		for (Column column : STRING_COLUMNS) {
			builder.append("  ").append(column.name()).append('\n');
		}
		builder.append("\nDATA columns:\n");
		for (Column column : DATA_COLUMNS) {
			builder.append("  ").append(column.name()).append('\n');
		}
		builder.append("\nREFERENCE columns:\n");
		for (Column column : REFERENCE_COLUMNS) {
			builder.append("  ").append(column.name()).append('\n');
		}
		builder.append("\nSYMBOL columns:\n");
		for (Column column : SYMBOL_COLUMNS) {
			builder.append("  ").append(column.name()).append('\n');
		}
		builder.append("\nExamples:\n");
		builder.append("  SELECT 1;\n");
		builder.append("  SELECT prompt(\"hello world\");\n");
		builder.append("  SELECT name, entry FROM FUNCTION LIMIT 5;\n");
		builder.append("  SELECT UNIQUE namespace FROM FUNCTION ORDER BY namespace LIMIT 20;\n");
		builder.append("  SELECT * FROM STRING WHERE value LIKE 'usage:%';\n");
		builder.append("  SELECT address, value, length FROM STRING WHERE value LIKE '%http%' ")
				.append("ORDER BY address LIMIT 20;\n");
		builder.append("  SELECT address, name, data_type, value_text FROM DATA ")
				.append("WHERE is_global = true ORDER BY address LIMIT 20;\n");
		builder.append("  SELECT address, data_type, value FROM DATA WHERE is_constant = true ")
				.append("ORDER BY address LIMIT 20;\n");
		builder.append("  SELECT from_address, to_address, type FROM REFERENCE ")
				.append("WHERE to_address = 0x4044d1 LIMIT 20;\n");
		builder.append("  SELECT from_address, to_address, type FROM REFERENCE ")
				.append("WHERE type IN ('COMPUTED_CALL', 'UNCONDITIONAL_CALL') LIMIT 50;\n");
		builder.append("  SELECT UNIQUE caller.entry, caller.name, r.from_address ")
				.append("FROM REFERENCE r JOIN FUNCTION callee ON r.to_address = callee.entry ")
				.append("JOIN FUNCTION caller ON r.from_address >= caller.body_min ")
				.append("AND r.from_address <= caller.body_max WHERE callee.entry = 0x4044d1 ")
				.append("AND r.type IN ('COMPUTED_CALL', 'UNCONDITIONAL_CALL') ")
				.append("ORDER BY caller.name LIMIT 100;\n");
		builder.append("  SELECT entry, name FROM FUNCTION WHERE entry >= 0x4044d1;\n");
		builder.append("  SELECT entry, name FROM FUNCTION WHERE entry IN ")
				.append("(0x4044d1, 0x404500);\n");
		builder.append("  SELECT entry, name, callgraph_level(entry) FROM FUNCTION ")
				.append("ORDER BY callgraph_level(entry) DESC LIMIT 50;\n");
		builder.append("  SELECT concat(namespace, '::', name), entry FROM FUNCTION LIMIT 20;\n");
		builder.append("  SELECT entry, name, decompilation(entry) FROM FUNCTION ")
				.append("WHERE entry = 0x4044d1;\n");
		builder.append("  SELECT entry, name, instructions(entry) FROM FUNCTION ")
				.append("WHERE entry = 0x4044d1;\n");
		builder.append("  SELECT prompt(\"hello world\") FROM FUNCTION;\n");
		builder.append("  SELECT name, prompt(name) FROM FUNCTION LIMIT 2;\n");
		builder.append("  SELECT count(1) func_count FROM FUNCTION;\n");
		builder.append("  SELECT callgraph_level(entry) lvl, count(*) FROM FUNCTION ")
				.append("GROUP BY lvl;\n");
		builder.append("  SELECT name, entry FROM FUNCTION WHERE name LIKE 'FUN_%' ")
				.append("ORDER BY entry LIMIT 20;\n");
		builder.append("  SELECT name, entry FROM FUNCTION WHERE is_thunk = false ")
				.append("AND name NOT LIKE 'FUN_%' LIMIT 20;\n");
		builder.append("  SELECT name, entry FROM FUNCTION WHERE is_external = true ")
				.append("OR (is_thunk = false AND name NOT LIKE 'FUN_%') LIMIT 20;\n");
		builder.append("  UPDATE FUNCTION SET name = 'foobar' WHERE entry = 0x4044d1;\n");
		builder.append("  UPDATE FUNCTION SET name = prompt('Suggest a function name') ")
				.append("WHERE entry = 0x4044d1;\n");
		builder.append("  UPDATE DATA SET name = 'global_config' WHERE address = 0x405000;\n");
		builder.append("  UPDATE SYMBOL SET name = 'dispatch_table' WHERE address = 0x406000;\n");
		builder.append("\nSupported WHERE operators: =, !=, <, <=, >, >=, BETWEEN, ")
				.append("IN, NOT IN, LIKE, NOT LIKE.");
		builder.append("\nJOIN supports explicit inner joins with ON predicates, table aliases, ")
				.append("and qualified columns such as caller.name.");
		builder.append("\nWHERE predicates can be combined with AND, OR, and parentheses.");
		builder.append("\nNumeric literals can be decimal or hexadecimal, for example 0x4044d1.");
		builder.append("\nBuilt-in functions: concat(value1, value2, ...), where NULL arguments ")
				.append("are treated as empty strings; count(*), count(1), count(column), ")
				.append("callgraph_level(entry), where root/entry functions are 0 and callees ")
				.append("increase in level; decompilation(entry), instructions(entry), and ")
				.append("prompt(expression) in SELECT. Constant prompt() expressions return one row; ")
				.append("row-dependent prompt() expressions invoke the model for each displayed row.");
		return builder.toString();
	}

	String execute(String queryText) {
		return execute(queryText, SpecterStreamingResponseListener.IGNORE);
	}

	String execute(String queryText, SpecterStreamingResponseListener listener) {
		SqlStatement statement = new Parser(queryText).parse();
		if (statement instanceof Query query) {
			return executeSelectQuery(query, listener).renderedOutput();
		}
		if (statement instanceof UpdateStatement updateStatement) {
			return executeUpdate(updateStatement, listener);
		}
		throw new IllegalArgumentException("Unsupported SQL statement.");
	}

	boolean isWriteStatement(String queryText) {
		return new Parser(queryText).parse() instanceof UpdateStatement;
	}

	SqlResult executeStructured(String queryText) {
		return executeStructured(queryText, SpecterStreamingResponseListener.IGNORE);
	}

	SqlResult executeStructured(String queryText, SpecterStreamingResponseListener listener) {
		SqlStatement statement = new Parser(queryText).parse();
		if (!(statement instanceof Query query)) {
			throw new IllegalArgumentException("Structured results are only supported for SELECT queries.");
		}
		return executeSelectQuery(query, listener);
	}

	private SqlResult executeSelectQuery(Query query, SpecterStreamingResponseListener listener) {
		Program program = query.hasFromClause() ? requireProgram() : programSupplier.get();

		EvaluationContext context = new EvaluationContext(program, query.from(), listener);
		try {
			List<ValueExpression> expressions = expandStarExpressions(query.expressions(), context);
			Query resolvedQuery = query.withExpressions(expressions);
			if (isRowIndependentPromptQuery(resolvedQuery)) {
				return executeRowIndependentPromptQuery(resolvedQuery, context);
			}
			List<SqlRow> rows = query.hasFromClause() ?
				collectRows(program, context, query.from()) : List.of(SyntheticRow.INSTANCE);
			List<SqlRow> matches = new ArrayList<>();
			for (SqlRow row : rows) {
				if (query.where() == null || query.where().matches(row, context)) {
					matches.add(row);
				}
			}

			if (!query.groupBy().isEmpty()) {
				return executeGroupedQuery(resolvedQuery, matches, context);
			}

			if (containsAggregateExpression(resolvedQuery.expressions())) {
				return executeAggregateQuery(resolvedQuery, matches, context);
			}

			if (query.orderBy() != null) {
				matches.sort((left, right) -> compareForOrdering(
					query.orderBy().expression().evaluate(left, context),
					query.orderBy().expression().evaluate(right, context),
					query.orderBy().ascending()));
			}

			int requestedLimit = query.limit() == null ? DEFAULT_ROW_LIMIT : query.limit();
			int effectiveLimit = Math.min(requestedLimit, MAX_ROW_LIMIT);
			List<SqlRow> displayedRows =
				matches.subList(0, Math.min(effectiveLimit, matches.size()));
			List<String> labels = resolvedQuery.expressions().stream().map(ValueExpression::label).toList();
			List<Boolean> blockColumns =
				resolvedQuery.expressions().stream().map(ValueExpression::containsBlockOutput).toList();
			List<List<Object>> values;
			int resultCount = matches.size();
			if (query.unique()) {
				List<List<Object>> uniqueValues =
					uniqueRows(evaluateRows(resolvedQuery.expressions(), matches, context));
				resultCount = uniqueValues.size();
				values = uniqueValues.subList(0, Math.min(effectiveLimit, uniqueValues.size()));
			}
			else {
				values = evaluateRows(resolvedQuery.expressions(), displayedRows, context);
			}
			String rendered = render(labels, values, blockColumns, resultCount, effectiveLimit);
			return new SqlResult(labels, values, rendered);
		}
		finally {
			context.dispose();
		}
	}

	private SqlResult executeRowIndependentPromptQuery(Query query, EvaluationContext context) {
		List<String> labels = query.expressions().stream().map(ValueExpression::label).toList();
		List<Boolean> blockColumns =
			query.expressions().stream().map(ValueExpression::containsBlockOutput).toList();
		List<Object> rowValues = new ArrayList<>();
		for (ValueExpression expression : query.expressions()) {
			rowValues.add(expression.evaluate(null, context));
		}
		List<List<Object>> values = List.of(copyCellValues(rowValues));
		int effectiveLimit = Math.min(query.limit() == null ? DEFAULT_ROW_LIMIT : query.limit(),
			MAX_ROW_LIMIT);
		String rendered = render(labels, values, blockColumns, values.size(), effectiveLimit);
		return new SqlResult(labels, values, rendered);
	}

	private static boolean isRowIndependentPromptQuery(Query query) {
		if (query.where() != null || !query.groupBy().isEmpty() || query.orderBy() != null ||
			containsAggregateExpression(query.expressions()) || !containsPromptExpression(query.expressions())) {
			return false;
		}
		for (ValueExpression expression : query.expressions()) {
			if (expression.dependsOnRow()) {
				return false;
			}
		}
		return true;
	}

	private Program requireProgram() {
		Program program = programSupplier.get();
		if (program == null) {
			throw new IllegalStateException("No current program is open in Ghidra.");
		}
		return program;
	}

	private List<SqlRow> collectRows(Program program, EvaluationContext context,
			FromClause fromClause) {
		TableBinding baseBinding = context.requireBinding(fromClause.base().alias());
		List<SqlRow> baseRows = collectRows(program, baseBinding.schema());
		if (fromClause.joins().isEmpty()) {
			return baseRows;
		}

		List<SqlRow> joinedRows = new ArrayList<>();
		for (SqlRow baseRow : baseRows) {
			joinedRows.add(JoinedRow.of(baseBinding, baseRow));
		}

		for (JoinClause join : fromClause.joins()) {
			TableBinding joinBinding = context.requireBinding(join.table().alias());
			List<SqlRow> rightRows = collectRows(program, joinBinding.schema());
			List<SqlRow> nextRows = new ArrayList<>();
			for (SqlRow joinedRow : joinedRows) {
				for (SqlRow rightRow : rightRows) {
					JoinedRow candidate = ((JoinedRow) joinedRow).with(joinBinding, rightRow);
					if (join.on().matches(candidate, context)) {
						nextRows.add(candidate);
					}
				}
			}
			joinedRows = nextRows;
		}
		return joinedRows;
	}

	private String executeUpdate(UpdateStatement updateStatement,
			SpecterStreamingResponseListener listener) {
		if (!"name".equals(normalizeIdentifier(updateStatement.columnName()))) {
			throw new IllegalArgumentException("Only name columns can be updated.");
		}

		Program program = programSupplier.get();
		if (program == null) {
			throw new IllegalStateException("No current program is open in Ghidra.");
		}

		return switch (updateStatement.tableName()) {
			case FUNCTION_TABLE -> executeFunctionNameUpdate(program, updateStatement, listener);
			case DATA_TABLE -> executeDataNameUpdate(program, updateStatement, listener);
			case SYMBOL_TABLE -> executeSymbolNameUpdate(program, updateStatement, listener);
			default -> throw new IllegalArgumentException("Unknown table '" + updateStatement.tableName() +
				"'. UPDATE tables: FUNCTION, DATA, SYMBOL.");
		};
	}

	private String executeFunctionNameUpdate(Program program, UpdateStatement updateStatement,
			SpecterStreamingResponseListener listener) {
		List<FunctionRow> rows = collectFunctionRows(program);
		List<FunctionRow> matches = new ArrayList<>();
		Map<Address, String> newNamesByAddress = new LinkedHashMap<>();
		EvaluationContext context = new EvaluationContext(program, FUNCTION_SCHEMA, listener);
		try {
			for (FunctionRow row : rows) {
				if (updateStatement.where().matches(row, context)) {
					matches.add(row);
					newNamesByAddress.put(row.entry().address(), evaluateUpdateName(updateStatement, row,
						context));
				}
			}
		}
		finally {
			context.dispose();
		}
		if (matches.isEmpty()) {
			return "Rows updated: 0";
		}

		int transactionId = program.startTransaction("Specter SQL update FUNCTION.name");
		boolean commit = false;
		try {
			for (FunctionRow row : matches) {
				ghidra.program.model.listing.Function function =
					program.getFunctionManager().getFunctionAt(row.entry().address());
				if (function == null) {
					throw new IllegalStateException("No function exists at " + row.entry() + ".");
				}
				function.setName(newNamesByAddress.get(row.entry().address()), EDIT_SOURCE_TYPE);
			}
			commit = true;
			return "Rows updated: " + matches.size();
		}
		catch (Exception e) {
			throw new IllegalStateException("SQL update failed: " + e.getMessage(), e);
		}
		finally {
			program.endTransaction(transactionId, commit);
		}
	}

	private String executeDataNameUpdate(Program program, UpdateStatement updateStatement,
			SpecterStreamingResponseListener listener) {
		List<DataRow> rows = collectDataRows(program);
		List<DataRow> matches = new ArrayList<>();
		Map<Address, String> newNamesByAddress = new LinkedHashMap<>();
		EvaluationContext context = new EvaluationContext(program, DATA_SCHEMA, listener);
		try {
			for (DataRow row : rows) {
				if (updateStatement.where().matches(row, context)) {
					matches.add(row);
					newNamesByAddress.put(row.address().address(), evaluateUpdateName(updateStatement, row,
						context));
				}
			}
		}
		finally {
			context.dispose();
		}
		if (matches.isEmpty()) {
			return "Rows updated: 0";
		}

		int transactionId = program.startTransaction("Specter SQL update DATA.name");
		boolean commit = false;
		try {
			for (DataRow row : matches) {
				renameOrCreatePrimarySymbol(program, row.address().address(),
					newNamesByAddress.get(row.address().address()));
			}
			commit = true;
			return "Rows updated: " + matches.size();
		}
		catch (Exception e) {
			throw new IllegalStateException("SQL update failed: " + e.getMessage(), e);
		}
		finally {
			program.endTransaction(transactionId, commit);
		}
	}

	private String executeSymbolNameUpdate(Program program, UpdateStatement updateStatement,
			SpecterStreamingResponseListener listener) {
		List<SymbolRow> rows = collectSymbolRows(program);
		List<SymbolRow> matches = new ArrayList<>();
		Map<Address, String> newNamesByAddress = new LinkedHashMap<>();
		EvaluationContext context = new EvaluationContext(program, SYMBOL_SCHEMA, listener);
		try {
			for (SymbolRow row : rows) {
				if (updateStatement.where().matches(row, context)) {
					matches.add(row);
					newNamesByAddress.put(row.address().address(), evaluateUpdateName(updateStatement, row,
						context));
				}
			}
		}
		finally {
			context.dispose();
		}
		if (matches.isEmpty()) {
			return "Rows updated: 0";
		}

		int transactionId = program.startTransaction("Specter SQL update SYMBOL.name");
		boolean commit = false;
		try {
			for (SymbolRow row : matches) {
				renameOrCreatePrimarySymbol(program, row.address().address(),
					newNamesByAddress.get(row.address().address()));
			}
			commit = true;
			return "Rows updated: " + matches.size();
		}
		catch (Exception e) {
			throw new IllegalStateException("SQL update failed: " + e.getMessage(), e);
		}
		finally {
			program.endTransaction(transactionId, commit);
		}
	}

	private String evaluateUpdateName(UpdateStatement updateStatement, SqlRow row,
			EvaluationContext context) {
		Object value = updateStatement.value().evaluate(row, context);
		if (!(value instanceof String newName) || newName.isBlank()) {
			throw new IllegalArgumentException("name must be set to a non-empty string value.");
		}
		return newName.strip();
	}

	private static void renameOrCreatePrimarySymbol(Program program, Address address, String newName)
			throws InvalidInputException, DuplicateNameException {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol primarySymbol = symbolTable.getPrimarySymbol(address);
		if (primarySymbol != null && !primarySymbol.isDynamic()) {
			primarySymbol.setName(newName, EDIT_SOURCE_TYPE);
			return;
		}

		Symbol createdSymbol = symbolTable.createLabel(address, newName, EDIT_SOURCE_TYPE);
		createdSymbol.setPrimary();
	}

	private SqlResult executeAggregateQuery(Query query, List<SqlRow> matches,
			EvaluationContext context) {
		if (query.orderBy() != null) {
			throw new IllegalArgumentException("ORDER BY is not supported with aggregate queries.");
		}
		for (ValueExpression expression : query.expressions()) {
			if (!expression.isAggregate()) {
				throw new IllegalArgumentException(
					"Aggregate expressions cannot be mixed with row expressions.");
			}
		}

		List<String> labels = query.expressions().stream().map(ValueExpression::label).toList();
		List<Object> aggregateValues = new ArrayList<>();
		for (ValueExpression expression : query.expressions()) {
			aggregateValues.add(expression.evaluateAggregate(matches, context));
		}
		List<List<Object>> values = List.of(copyCellValues(aggregateValues));
		String rendered = render(labels, values, List.of(), values.size(), values.size());
		return new SqlResult(labels, values, rendered);
	}

	private SqlResult executeGroupedQuery(Query query, List<SqlRow> matches,
			EvaluationContext context) {
		for (ValueExpression expression : query.groupBy()) {
			if (expression.isAggregate()) {
				throw new IllegalArgumentException("Aggregate expressions are not supported in GROUP BY.");
			}
			String blockFunctionName = expression.blockOutputFunctionName();
			if (blockFunctionName != null) {
				throw new IllegalArgumentException(blockFunctionName + " is not supported in GROUP BY.");
			}
		}
		for (ValueExpression expression : query.expressions()) {
			if (!expression.isAggregate() && !isGroupedExpression(expression, query.groupBy())) {
				throw new IllegalArgumentException(
					"Grouped queries can only select aggregate expressions or GROUP BY expressions.");
			}
		}
		if (query.orderBy() != null) {
			throw new IllegalArgumentException("ORDER BY is not supported with GROUP BY yet.");
		}

		Map<GroupKey, List<SqlRow>> groups = new LinkedHashMap<>();
		for (SqlRow row : matches) {
			List<Object> keyValues = new ArrayList<>();
			for (ValueExpression expression : query.groupBy()) {
				keyValues.add(expression.evaluate(row, context));
			}
			groups.computeIfAbsent(new GroupKey(keyValues), ignored -> new ArrayList<>()).add(row);
		}

		List<Map.Entry<GroupKey, List<SqlRow>>> orderedGroups =
			new ArrayList<>(groups.entrySet());
		orderedGroups.sort((left, right) -> compareGroupKeys(left.getKey(), right.getKey()));

		List<List<Object>> values = new ArrayList<>();
		for (Map.Entry<GroupKey, List<SqlRow>> group : orderedGroups) {
			List<SqlRow> groupRows = group.getValue();
			SqlRow firstRow = groupRows.get(0);
			List<Object> rowValues = new ArrayList<>();
			for (ValueExpression expression : query.expressions()) {
				if (expression.isAggregate()) {
					rowValues.add(expression.evaluateAggregate(groupRows, context));
				}
				else {
					rowValues.add(expression.evaluate(firstRow, context));
				}
			}
			values.add(copyCellValues(rowValues));
		}

		int requestedLimit = query.limit() == null ? DEFAULT_ROW_LIMIT : query.limit();
		int effectiveLimit = Math.min(requestedLimit, MAX_ROW_LIMIT);
		if (query.unique()) {
			values = uniqueRows(values);
		}
		List<List<Object>> displayedValues =
			values.subList(0, Math.min(effectiveLimit, values.size()));
		List<String> labels = query.expressions().stream().map(ValueExpression::label).toList();
		String rendered = render(labels, displayedValues, List.of(), values.size(), effectiveLimit);
		return new SqlResult(labels, displayedValues, rendered);
	}

	private static int compareGroupKeys(GroupKey left, GroupKey right) {
		int keyCount = Math.min(left.values().size(), right.values().size());
		for (int i = 0; i < keyCount; i++) {
			int comparison = compareForOrdering(left.values().get(i), right.values().get(i), true);
			if (comparison != 0) {
				return comparison;
			}
		}
		return Integer.compare(left.values().size(), right.values().size());
	}

	private List<FunctionRow> collectFunctionRows(Program program) {
		List<FunctionRow> rows = new ArrayList<>();
		FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
		while (iterator.hasNext()) {
			ghidra.program.model.listing.Function function = iterator.next();
			AddressSetView body = function.getBody();
			Address bodyMin = body == null || body.isEmpty() ? null : body.getMinAddress();
			Address bodyMax = body == null || body.isEmpty() ? null : body.getMaxAddress();
			long bodySize = body == null ? 0 : body.getNumAddresses();
			String source = function.getSymbol() == null ? "" : String.valueOf(function.getSymbol().getSource());
			rows.add(new FunctionRow(
				new AddressValue(function.getEntryPoint()),
				function.getName(),
				String.valueOf(function.getParentNamespace()),
				function.getPrototypeString(true, false),
				String.valueOf(function.getReturnType()),
				function.getParameterCount(),
				bodyMin == null ? null : new AddressValue(bodyMin),
				bodyMax == null ? null : new AddressValue(bodyMax),
				bodySize,
				function.isExternal(),
				function.isThunk(),
				nullToEmpty(function.getCallingConventionName()),
				source));
		}
		return rows;
	}

	private List<SqlRow> collectRows(Program program, TableSchema schema) {
		if (FUNCTION_TABLE.equals(schema.name())) {
			return new ArrayList<>(collectFunctionRows(program));
		}
		if (STRING_TABLE.equals(schema.name())) {
			return new ArrayList<>(collectStringRows(program));
		}
		if (DATA_TABLE.equals(schema.name())) {
			return new ArrayList<>(collectDataRows(program));
		}
		if (REFERENCE_TABLE.equals(schema.name())) {
			return new ArrayList<>(collectReferenceRows(program));
		}
		if (SYMBOL_TABLE.equals(schema.name())) {
			return new ArrayList<>(collectSymbolRows(program));
		}
		throw new IllegalArgumentException("Unknown table '" + schema.name() + "'.");
	}

	private List<SymbolRow> collectSymbolRows(Program program) {
		List<SymbolRow> rows = new ArrayList<>();
		SymbolIterator iterator = program.getSymbolTable().getAllSymbols(true);
		while (iterator.hasNext()) {
			Symbol symbol = iterator.next();
			Address address = symbol.getAddress();
			if (address == null) {
				continue;
			}
			rows.add(new SymbolRow(
				new AddressValue(address),
				symbol.getName(),
				String.valueOf(symbol.getParentNamespace()),
				String.valueOf(symbol.getSource())));
		}
		return rows;
	}

	private List<ReferenceRow> collectReferenceRows(Program program) {
		List<ReferenceRow> rows = new ArrayList<>();
		Address minAddress = program.getMinAddress();
		if (minAddress == null) {
			return rows;
		}
		ReferenceIterator iterator =
			program.getReferenceManager().getReferenceIterator(minAddress);
		while (iterator.hasNext()) {
			Reference reference = iterator.next();
			Address fromAddress = reference.getFromAddress();
			Address toAddress = reference.getToAddress();
			rows.add(new ReferenceRow(
				toAddressValue(fromAddress),
				toAddressValue(toAddress),
				String.valueOf(reference.getReferenceType()),
				String.valueOf(reference.getSource())));
		}
		return rows;
	}

	private static AddressValue toAddressValue(Address address) {
		return address == null ? null : new AddressValue(address);
	}

	private List<StringRow> collectStringRows(Program program) {
		List<StringRow> rows = new ArrayList<>();
		for (Data data : DefinedStringIterator.forProgram(program)) {
			StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
			if (stringData == null) {
				continue;
			}
			String value = stringData.getStringValue();
			rows.add(new StringRow(
				new AddressValue(data.getAddress()),
				value,
				data.getDataType().getDisplayName(),
				value == null ? 0 : value.length()));
		}
		return rows;
	}

	private List<DataRow> collectDataRows(Program program) {
		List<DataRow> rows = new ArrayList<>();
		DataIterator iterator = program.getListing().getDefinedData(true);
		while (iterator.hasNext()) {
			Data data = iterator.next();
			Symbol primarySymbol = data.getPrimarySymbol();
			ghidra.program.model.listing.Function containingFunction =
				program.getFunctionManager().getFunctionContaining(data.getMinAddress());
			Object rawValue = data.getValue();
			rows.add(new DataRow(
				new AddressValue(data.getMinAddress()),
				nullToEmpty(data.getLabel()),
				primarySymbol == null ? "" : String.valueOf(primarySymbol.getParentNamespace()),
				data.getDataType().getDisplayName(),
				data.getBaseDataType().getDisplayName(),
				data.getLength(),
				comparableDataValue(rawValue),
				dataValueText(data, rawValue),
				data.isConstant(),
				data.isWritable(),
				data.isVolatile(),
				data.isPointer(),
				data.isArray(),
				data.hasStringValue(),
				containingFunction == null,
				containingFunction == null ? "" : containingFunction.getName(),
				primarySymbol == null ? "" : String.valueOf(primarySymbol.getSource()),
				countReferencesTo(program.getReferenceManager(), data.getMinAddress())));
		}
		return rows;
	}

	private static Object comparableDataValue(Object value) {
		if (value instanceof Scalar scalar) {
			return scalar.getUnsignedValue();
		}
		if (value instanceof Number || value instanceof String || value instanceof Boolean ||
			value instanceof AddressValue) {
			return value;
		}
		return value == null ? null : String.valueOf(value);
	}

	private static String dataValueText(Data data, Object value) {
		String representation = data.getDefaultValueRepresentation();
		if (representation != null && !representation.isBlank()) {
			return representation;
		}
		return value == null ? "" : String.valueOf(value);
	}

	private static int countReferencesTo(ReferenceManager referenceManager, Address address) {
		int count = 0;
		Iterable<Reference> references = referenceManager.getReferencesTo(address);
		for (Reference ignored : references) {
			count++;
		}
		return count;
	}

	private List<List<Object>> evaluateRows(List<ValueExpression> expressions, List<SqlRow> rows,
			EvaluationContext context) {
		List<List<Object>> values = new ArrayList<>();
		for (SqlRow row : rows) {
			List<Object> rowValues = new ArrayList<>();
			for (ValueExpression expression : expressions) {
				rowValues.add(expression.evaluate(row, context));
			}
			values.add(copyCellValues(rowValues));
		}
		return copyResultRows(values);
	}

	private String render(List<String> labels, List<List<Object>> rows, List<Boolean> blockColumns,
			int matchCount, int effectiveLimit) {
		StringBuilder builder = new StringBuilder();
		builder.append("Rows: ").append(rows.size()).append(" displayed");
		if (matchCount != rows.size()) {
			builder.append(" of ").append(matchCount);
		}
		if (matchCount > effectiveLimit) {
			builder.append(" (truncated to ").append(effectiveLimit).append(")");
		}
		builder.append("\n\n");

		if (labels.isEmpty()) {
			builder.append("No columns selected.");
			return builder.toString();
		}
		if (rows.isEmpty()) {
			builder.append("No rows matched.");
			return builder.toString();
		}

		if (containsTrue(blockColumns)) {
			appendBlockRows(builder, labels, rows, blockColumns);
			return builder.toString();
		}

		List<Integer> widths = computeWidths(labels, rows);
		appendTableRow(builder, labels, widths);
		appendSeparator(builder, widths);
		for (List<Object> row : rows) {
			List<String> values = new ArrayList<>();
			for (Object value : row) {
				values.add(formatCell(value));
			}
			appendTableRow(builder, values, widths);
			if (builder.length() > MAX_RENDERED_LENGTH) {
				builder.setLength(MAX_RENDERED_LENGTH);
				builder.append("\n... output truncated.");
				break;
			}
		}
		return builder.toString();
	}

	private void appendBlockRows(StringBuilder builder, List<String> labels, List<List<Object>> rows,
			List<Boolean> blockColumns) {
		for (int rowIndex = 0; rowIndex < rows.size(); rowIndex++) {
			List<Object> row = rows.get(rowIndex);
			if (rowIndex > 0) {
				builder.append('\n');
			}
			builder.append("Row ").append(rowIndex + 1).append(":\n");
			for (int columnIndex = 0; columnIndex < labels.size(); columnIndex++) {
				String label = labels.get(columnIndex);
				Object value = row.get(columnIndex);
				builder.append(label).append(":\n");
				if (columnIndex < blockColumns.size() && blockColumns.get(columnIndex)) {
					builder.append(formatBlockValue(value)).append('\n');
				}
				else {
					builder.append("  ").append(formatCell(value)).append('\n');
				}
			}
			if (builder.length() > MAX_RENDERED_LENGTH) {
				builder.setLength(MAX_RENDERED_LENGTH);
				builder.append("\n... output truncated.");
				break;
			}
		}
	}

	private static boolean containsTrue(List<Boolean> values) {
		for (Boolean value : values) {
			if (Boolean.TRUE.equals(value)) {
				return true;
			}
		}
		return false;
	}

	private static boolean containsAggregateExpression(List<ValueExpression> expressions) {
		for (ValueExpression expression : expressions) {
			if (expression.isAggregate()) {
				return true;
			}
		}
		return false;
	}

	private static boolean containsPromptExpression(List<ValueExpression> expressions) {
		for (ValueExpression expression : expressions) {
			if (containsPromptExpression(expression)) {
				return true;
			}
		}
		return false;
	}

	private static boolean containsPromptExpression(ValueExpression expression) {
		if (expression instanceof AliasedExpression aliasedExpression) {
			return containsPromptExpression(aliasedExpression.delegate());
		}
		if (expression instanceof FunctionCallExpression functionCallExpression) {
			if (PROMPT_FUNCTION.equals(normalizeIdentifier(functionCallExpression.name()))) {
				return true;
			}
			return containsPromptExpression(functionCallExpression.arguments());
		}
		return false;
	}

	private static List<Object> copyCellValues(List<Object> values) {
		return new ArrayList<>(values);
	}

	private static List<List<Object>> copyResultRows(List<List<Object>> rows) {
		List<List<Object>> copy = new ArrayList<>();
		for (List<Object> row : rows) {
			copy.add(copyCellValues(row));
		}
		return copy;
	}

	private static List<List<Object>> uniqueRows(List<List<Object>> rows) {
		Set<List<Object>> seen = new HashSet<>();
		List<List<Object>> uniqueRows = new ArrayList<>();
		for (List<Object> row : rows) {
			List<Object> key = copyCellValues(row);
			if (seen.add(key)) {
				uniqueRows.add(copyCellValues(row));
			}
		}
		return uniqueRows;
	}

	private static boolean isGroupedExpression(ValueExpression expression,
			List<ValueExpression> groupByExpressions) {
		for (ValueExpression groupByExpression : groupByExpressions) {
			if (sameExpressionLabel(expression, groupByExpression)) {
				return true;
			}
		}
		return false;
	}

	private static boolean sameExpressionLabel(ValueExpression left, ValueExpression right) {
		Set<String> leftLabels = expressionLabels(left);
		for (String label : expressionLabels(right)) {
			if (leftLabels.contains(label)) {
				return true;
			}
		}
		return false;
	}

	private static Set<String> expressionLabels(ValueExpression expression) {
		Set<String> labels = new HashSet<>();
		labels.add(normalizeIdentifier(expression.label()));
		if (expression instanceof AliasedExpression aliasedExpression) {
			labels.add(normalizeIdentifier(aliasedExpression.delegate().label()));
		}
		return labels;
	}

	private List<Integer> computeWidths(List<String> labels, List<List<Object>> rows) {
		List<Integer> widths = new ArrayList<>();
		for (String label : labels) {
			widths.add(Math.min(MAX_CELL_WIDTH, label.length()));
		}
		for (List<Object> row : rows) {
			for (int i = 0; i < labels.size(); i++) {
				int width = formatCell(row.get(i)).length();
				widths.set(i, Math.min(MAX_CELL_WIDTH, Math.max(widths.get(i), width)));
			}
		}
		return widths;
	}

	private void appendTableRow(StringBuilder builder, List<String> values, List<Integer> widths) {
		for (int i = 0; i < values.size(); i++) {
			if (i > 0) {
				builder.append(" | ");
			}
			builder.append(padRight(abbreviate(values.get(i), widths.get(i)), widths.get(i)));
		}
		builder.append('\n');
	}

	private void appendSeparator(StringBuilder builder, List<Integer> widths) {
		for (int i = 0; i < widths.size(); i++) {
			if (i > 0) {
				builder.append("-+-");
			}
			builder.append("-".repeat(widths.get(i)));
		}
		builder.append('\n');
	}

	private static String padRight(String value, int width) {
		if (value.length() >= width) {
			return value;
		}
		return value + " ".repeat(width - value.length());
	}

	private static String abbreviate(String value, int maxLength) {
		if (value.length() <= maxLength) {
			return value;
		}
		if (maxLength <= 3) {
			return value.substring(0, maxLength);
		}
		return value.substring(0, maxLength - 3) + "...";
	}

	private static String formatCell(Object value) {
		if (value == null) {
			return "NULL";
		}
		return String.valueOf(value).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
	}

	private static String formatBlockValue(Object value) {
		if (value == null) {
			return "NULL";
		}
		return String.valueOf(value).stripTrailing();
	}

	private static String formatPromptContextValue(Object value) {
		if (value == null) {
			return "NULL";
		}
		String formatted = String.valueOf(value)
				.replace('\n', ' ')
				.replace('\r', ' ')
				.replace('\t', ' ');
		return abbreviate(formatted, MAX_PROMPT_CONTEXT_VALUE_LENGTH);
	}

	private static List<ValueExpression> expandStarExpressions(List<ValueExpression> expressions,
			EvaluationContext context) {
		List<ValueExpression> expanded = new ArrayList<>();
		for (ValueExpression expression : expressions) {
			if (expression instanceof StarExpression) {
				if (context.bindings().isEmpty()) {
					throw new IllegalArgumentException("SELECT * requires a FROM clause.");
				}
				for (TableBinding binding : context.bindings()) {
					for (Column column : binding.schema().columns()) {
						expanded.add(context.joined() ?
							new ColumnExpression(binding.alias(), column.name()) :
							new ColumnExpression(column.name()));
					}
				}
			}
			else {
				expanded.add(expression);
			}
		}
		return List.copyOf(expanded);
	}

	private static TableSchema requireTable(String tableName) {
		TableSchema schema = TABLES_BY_NAME.get(tableName.toUpperCase(Locale.ROOT));
		if (schema == null) {
			String normalizedTableName = normalizeIdentifier(tableName);
			if (INSTRUCTIONS_FUNCTION.equals(normalizedTableName) ||
				DECOMPILATION_FUNCTION.equals(normalizedTableName)) {
				throw new IllegalArgumentException("'" + tableName +
					"' is a SQL function, not a table. Use SELECT entry, name, " +
					normalizedTableName + "(entry) FROM FUNCTION WHERE entry = 0x...;");
			}
			throw new IllegalArgumentException("Unknown table '" + tableName +
				"'. Tables: FUNCTION, STRING, DATA, REFERENCE, SYMBOL.");
		}
		return schema;
	}

	private static Column requireColumn(TableSchema schema, String columnName) {
		Column column = schema.columnByName(columnName);
		if (column == null) {
			throw new IllegalArgumentException("Unknown " + schema.name() + " column '" +
				columnName + "'.");
		}
		return column;
	}

	private static String normalizeIdentifier(String identifier) {
		return identifier.toLowerCase(Locale.ROOT);
	}

	private static String nullToEmpty(String value) {
		return value == null ? "" : value;
	}

	static String formatSqlLiteral(Object value) {
		if (value == null) {
			return "NULL";
		}
		if (value instanceof Number || value instanceof Boolean) {
			return String.valueOf(value);
		}
		if (value instanceof AddressValue addressValue) {
			return "0x" + Long.toUnsignedString(addressValue.offset(), 16);
		}
		return "'" + String.valueOf(value).replace("'", "''") + "'";
	}

	private static int compareForOrdering(Object left, Object right, boolean ascending) {
		if (left == null && right == null) {
			return 0;
		}
		if (left == null) {
			return 1;
		}
		if (right == null) {
			return -1;
		}
		int comparison = ComparableValue.from(left).compareTo(ComparableValue.from(right));
		return ascending ? comparison : -comparison;
	}

	private record TableSchema(String name, List<Column> columns, Map<String, Column> columnsByName) {
		static TableSchema of(String name, List<Column> columns) {
			return new TableSchema(name, List.copyOf(columns), columns.stream().collect(
				java.util.stream.Collectors.toUnmodifiableMap(
					column -> normalizeIdentifier(column.name()), Function.identity())));
		}

		Column columnByName(String columnName) {
			return columnsByName.get(normalizeIdentifier(columnName));
		}
	}

	private interface SqlRow {
	}

	private enum SyntheticRow implements SqlRow {
		INSTANCE
	}

	private record TableReference(String tableName, String alias) {
		TableReference {
			tableName = tableName.toUpperCase(Locale.ROOT);
			alias = normalizeIdentifier(alias == null || alias.isBlank() ? tableName : alias);
		}
	}

	private record JoinClause(TableReference table, Condition on) {
	}

	private record FromClause(TableReference base, List<JoinClause> joins) {
		FromClause {
			joins = List.copyOf(joins);
		}
	}

	private record TableBinding(String tableName, String alias, TableSchema schema) {
	}

	private record BoundTableRow(TableBinding binding, SqlRow row) {
	}

	private record JoinedRow(Map<String, BoundTableRow> rowsByAlias) implements SqlRow {
		JoinedRow {
			rowsByAlias = Map.copyOf(rowsByAlias);
		}

		static JoinedRow of(TableBinding binding, SqlRow row) {
			Map<String, BoundTableRow> rows = new LinkedHashMap<>();
			rows.put(binding.alias(), new BoundTableRow(binding, row));
			return new JoinedRow(rows);
		}

		JoinedRow with(TableBinding binding, SqlRow row) {
			Map<String, BoundTableRow> rows = new LinkedHashMap<>(rowsByAlias);
			rows.put(binding.alias(), new BoundTableRow(binding, row));
			return new JoinedRow(rows);
		}

		SqlRow rowForAlias(String alias) {
			BoundTableRow boundRow = rowsByAlias.get(normalizeIdentifier(alias));
			if (boundRow == null) {
				throw new IllegalArgumentException("No joined row is bound for alias '" + alias + "'.");
			}
			return boundRow.row();
		}
	}

	private record Column(String name, Function<SqlRow, Object> extractor) {
		Object value(SqlRow row) {
			return extractor.apply(row);
		}
	}

	private interface ValueExpression {
		String label();

		Object evaluate(SqlRow row, EvaluationContext context);

		default boolean isAggregate() {
			return false;
		}

		default Object evaluateAggregate(List<SqlRow> rows, EvaluationContext context) {
			throw new IllegalStateException(label() + " is not an aggregate expression.");
		}

		default String blockOutputFunctionName() {
			return null;
		}

		default boolean containsBlockOutput() {
			return blockOutputFunctionName() != null;
		}

		default boolean dependsOnRow() {
			return true;
		}
	}

	private record CountExpression(CountArgument argument) implements ValueExpression {
		@Override
		public String label() {
			return COUNT_FUNCTION + "(" + argument.label() + ")";
		}

		@Override
		public Object evaluate(SqlRow row, EvaluationContext context) {
			throw new IllegalStateException(COUNT_FUNCTION + " is an aggregate expression.");
		}

		@Override
		public boolean isAggregate() {
			return true;
		}

		@Override
		public Object evaluateAggregate(List<SqlRow> rows, EvaluationContext context) {
			long count = 0;
			for (SqlRow row : rows) {
				if (argument.counts(row, context)) {
					count++;
				}
			}
			return count;
		}

		@Override
		public String blockOutputFunctionName() {
			return argument.blockOutputFunctionName();
		}
	}

	private record AliasedExpression(ValueExpression delegate, String alias) implements ValueExpression {
		@Override
		public String label() {
			return alias;
		}

		@Override
		public Object evaluate(SqlRow row, EvaluationContext context) {
			return delegate.evaluate(row, context);
		}

		@Override
		public boolean isAggregate() {
			return delegate.isAggregate();
		}

		@Override
		public Object evaluateAggregate(List<SqlRow> rows, EvaluationContext context) {
			return delegate.evaluateAggregate(rows, context);
		}

		@Override
		public String blockOutputFunctionName() {
			return delegate.blockOutputFunctionName();
		}

		@Override
		public boolean dependsOnRow() {
			return delegate.dependsOnRow();
		}
	}

	private interface CountArgument {
		String label();

		boolean counts(SqlRow row, EvaluationContext context);

		default String blockOutputFunctionName() {
			return null;
		}
	}

	private record CountAllArgument() implements CountArgument {
		@Override
		public String label() {
			return "*";
		}

		@Override
		public boolean counts(SqlRow row, EvaluationContext context) {
			return true;
		}
	}

	private record LiteralCountArgument(Literal literal) implements CountArgument {
		@Override
		public String label() {
			return formatSqlLiteral(literal.value());
		}

		@Override
		public boolean counts(SqlRow row, EvaluationContext context) {
			return literal.value() != null;
		}
	}

	private record ExpressionCountArgument(ValueExpression expression) implements CountArgument {
		@Override
		public String label() {
			return expression.label();
		}

		@Override
		public boolean counts(SqlRow row, EvaluationContext context) {
			return expression.evaluate(row, context) != null;
		}

		@Override
		public String blockOutputFunctionName() {
			return expression.blockOutputFunctionName();
		}
	}

	private record StarExpression() implements ValueExpression {
		@Override
		public String label() {
			return "*";
		}

		@Override
		public Object evaluate(SqlRow row, EvaluationContext context) {
			throw new IllegalStateException("SELECT * must be expanded before evaluation.");
		}
	}

	private record LiteralExpression(Literal literal) implements ValueExpression {
		@Override
		public String label() {
			return formatSqlLiteral(literal.value());
		}

		@Override
		public Object evaluate(SqlRow row, EvaluationContext context) {
			return literal.value();
		}

		@Override
		public boolean dependsOnRow() {
			return false;
		}
	}

	private record ColumnExpression(String qualifier, String columnName) implements ValueExpression {
		ColumnExpression(String columnName) {
			this(null, columnName);
		}

		@Override
		public String label() {
			return qualifier == null ? columnName : qualifier + "." + columnName;
		}

		@Override
		public Object evaluate(SqlRow row, EvaluationContext context) {
			return context.columnValue(row, qualifier, columnName);
		}

		@Override
		public boolean dependsOnRow() {
			return true;
		}
	}

	private record FunctionCallExpression(String name, List<ValueExpression> arguments)
			implements ValueExpression {
		@Override
		public String label() {
			return name + "(" +
				String.join(", ", arguments.stream().map(ValueExpression::label).toList()) + ")";
		}

		@Override
		public Object evaluate(SqlRow row, EvaluationContext context) {
			String normalizedName = normalizeIdentifier(name);
			if (CONCAT_FUNCTION.equals(normalizedName)) {
				return evaluateConcat(row, context);
			}
			Object value = arguments.get(0).evaluate(row, context);
			if (value == null) {
				return null;
			}
			if (PROMPT_FUNCTION.equals(normalizedName)) {
				return context.prompt(String.valueOf(value), row);
			}
			if (!context.hasTable(FUNCTION_TABLE)) {
				throw new IllegalArgumentException("SQL function '" + name +
					"' is only supported for the FUNCTION table.");
			}
			if (CALLGRAPH_LEVEL_FUNCTION.equals(normalizedName)) {
				return evaluateCallGraphLevel(value, context);
			}
			if (DECOMPILATION_FUNCTION.equals(normalizedName)) {
				return evaluateDecompilation(value, context);
			}
			if (INSTRUCTIONS_FUNCTION.equals(normalizedName)) {
				return evaluateInstructions(value, context);
			}
			throw new IllegalArgumentException("Unsupported SQL function '" + name + "'.");
		}

		private Object evaluateConcat(SqlRow row, EvaluationContext context) {
			StringBuilder builder = new StringBuilder();
			for (ValueExpression argument : arguments) {
				Object value = argument.evaluate(row, context);
				if (value != null) {
					builder.append(value);
				}
			}
			return builder.toString();
		}

		private Object evaluateCallGraphLevel(Object value, EvaluationContext context) {
			if (!(value instanceof AddressValue addressValue)) {
				throw new IllegalArgumentException(CALLGRAPH_LEVEL_FUNCTION +
					" expects an address-valued argument.");
			}
			return context.callGraphLevel(addressValue);
		}

		private Object evaluateDecompilation(Object value, EvaluationContext context) {
			if (!(value instanceof AddressValue addressValue)) {
				throw new IllegalArgumentException(DECOMPILATION_FUNCTION +
					" expects an address-valued argument.");
			}
			return context.decompilation(addressValue);
		}

		@Override
		public String blockOutputFunctionName() {
			String normalizedName = normalizeIdentifier(name);
			if (DECOMPILATION_FUNCTION.equals(normalizedName) ||
				INSTRUCTIONS_FUNCTION.equals(normalizedName) ||
				PROMPT_FUNCTION.equals(normalizedName)) {
				return normalizedName;
			}
			for (ValueExpression argument : arguments) {
				String blockFunctionName = argument.blockOutputFunctionName();
				if (blockFunctionName != null) {
					return blockFunctionName;
				}
			}
			return null;
		}

		@Override
		public boolean dependsOnRow() {
			for (ValueExpression argument : arguments) {
				if (argument.dependsOnRow()) {
					return true;
				}
			}
			return false;
		}

		private Object evaluateInstructions(Object value, EvaluationContext context) {
			if (!(value instanceof AddressValue addressValue)) {
				throw new IllegalArgumentException(INSTRUCTIONS_FUNCTION +
					" expects an address-valued argument.");
			}
			return context.instructions(addressValue);
		}
	}

	private record FunctionRow(
			AddressValue entry,
			String name,
			String namespace,
			String signature,
			String returnType,
			int parameterCount,
			AddressValue bodyMin,
			AddressValue bodyMax,
			long bodySize,
			boolean external,
			boolean thunk,
			String callingConvention,
			String source) implements SqlRow {
	}

	private record StringRow(
			AddressValue address,
			String value,
			String dataType,
			int length) implements SqlRow {
	}

	private record DataRow(
			AddressValue address,
			String name,
			String namespace,
			String dataType,
			String baseDataType,
			int length,
			Object value,
			String valueText,
			boolean constant,
			boolean writable,
			boolean volatileData,
			boolean pointer,
			boolean array,
			boolean string,
			boolean global,
			String containingFunction,
			String source,
			int referenceCount) implements SqlRow {
	}

	private record ReferenceRow(
			AddressValue fromAddress,
			AddressValue toAddress,
			String type,
			String source) implements SqlRow {
	}

	private record SymbolRow(
			AddressValue address,
			String name,
			String namespace,
			String source) implements SqlRow {
	}

	private record GroupKey(List<Object> values) {
		GroupKey {
			values = new ArrayList<>(values);
		}
	}

	record SqlResult(List<String> labels, List<List<Object>> rows, String renderedOutput) {
		SqlResult {
			labels = List.copyOf(labels);
			rows = List.copyOf(rows);
			renderedOutput = renderedOutput == null ? "" : renderedOutput;
		}
	}

	private interface SqlStatement {
	}

	private record Query(
			List<ValueExpression> expressions,
			FromClause from,
			boolean unique,
			Condition where,
			List<ValueExpression> groupBy,
			OrderBy orderBy,
			Integer limit) implements SqlStatement {
		Query withExpressions(List<ValueExpression> resolvedExpressions) {
			return new Query(resolvedExpressions, from, unique, where, groupBy, orderBy, limit);
		}

		boolean hasFromClause() {
			return from != null;
		}
	}

	private record UpdateStatement(
			String tableName,
			String columnName,
			ValueExpression value,
			Condition where) implements SqlStatement {
	}

	private record OrderBy(ValueExpression expression, boolean ascending) {
	}

	private interface Condition {
		boolean matches(SqlRow row, EvaluationContext context);
	}

	private record AndCondition(Condition left, Condition right) implements Condition {
		@Override
		public boolean matches(SqlRow row, EvaluationContext context) {
			return left.matches(row, context) && right.matches(row, context);
		}
	}

	private record OrCondition(Condition left, Condition right) implements Condition {
		@Override
		public boolean matches(SqlRow row, EvaluationContext context) {
			return left.matches(row, context) || right.matches(row, context);
		}
	}

	private record PredicateCondition(ValueExpression expression, Operator operator, PredicateValue expected)
			implements Condition {
		@Override
		public boolean matches(SqlRow row, EvaluationContext context) {
			Object actual = expression.evaluate(row, context);
			Object expectedValue = expected.evaluate(row, context);
			if (operator == Operator.LIKE || operator == Operator.NOT_LIKE) {
				boolean matches = actual != null && expectedValue != null &&
					like(formatCell(actual), formatCell(expectedValue));
				return operator == Operator.LIKE ? matches : !matches;
			}
			if (actual == null || expectedValue == null) {
				return operator == Operator.EQUALS ? actual == expectedValue :
					operator == Operator.NOT_EQUALS && actual != expectedValue;
			}

			int comparison = comparePredicateValues(actual, expectedValue);
			return switch (operator) {
				case EQUALS -> comparison == 0;
				case NOT_EQUALS -> comparison != 0;
				case LESS_THAN -> comparison < 0;
				case LESS_THAN_OR_EQUAL -> comparison <= 0;
				case GREATER_THAN -> comparison > 0;
				case GREATER_THAN_OR_EQUAL -> comparison >= 0;
				case LIKE, NOT_LIKE -> throw new IllegalStateException("LIKE handled separately.");
			};
		}

		private static boolean like(String value, String pattern) {
			StringBuilder regex = new StringBuilder();
			for (int i = 0; i < pattern.length(); i++) {
				char c = pattern.charAt(i);
				if (c == '%') {
					regex.append(".*");
				}
				else if (c == '_') {
					regex.append('.');
				}
				else {
					regex.append(Pattern.quote(String.valueOf(c)));
				}
			}
			return Pattern.compile(regex.toString(), Pattern.DOTALL).matcher(value).matches();
		}
	}

	private record BetweenCondition(ValueExpression expression, PredicateValue lower,
			PredicateValue upper) implements Condition {
		@Override
		public boolean matches(SqlRow row, EvaluationContext context) {
			Object actual = expression.evaluate(row, context);
			Object lowerValue = lower.evaluate(row, context);
			Object upperValue = upper.evaluate(row, context);
			return actual != null && lowerValue != null && upperValue != null &&
				comparePredicateValues(actual, lowerValue) >= 0 &&
				comparePredicateValues(actual, upperValue) <= 0;
		}
	}

	private record InCondition(ValueExpression expression, List<PredicateValue> values, boolean negated)
			implements Condition {
		InCondition {
			values = List.copyOf(values);
		}

		@Override
		public boolean matches(SqlRow row, EvaluationContext context) {
			Object actual = expression.evaluate(row, context);
			boolean matched = false;
			if (actual != null) {
				for (PredicateValue value : values) {
					Object candidate = value.evaluate(row, context);
					if (candidate != null && comparePredicateValues(actual, candidate) == 0) {
						matched = true;
						break;
					}
				}
			}
			return negated ? !matched : matched;
		}
	}

	private static int comparePredicateValues(Object actual, Object expected) {
		if (actual == null && expected == null) {
			return 0;
		}
		if (actual == null) {
			return 1;
		}
		if (expected == null) {
			return -1;
		}
		if (actual instanceof AddressValue actualAddress && expected instanceof Number expectedNumber) {
			return Long.compareUnsigned(actualAddress.offset(), expectedNumber.longValue());
		}
		if (actual instanceof Number actualNumber && expected instanceof AddressValue expectedAddress) {
			return Long.compareUnsigned(actualNumber.longValue(), expectedAddress.offset());
		}
		if (actual instanceof AddressValue actualAddress && expected instanceof AddressValue expectedAddress) {
			return Long.compareUnsigned(actualAddress.offset(), expectedAddress.offset());
		}
		if (actual instanceof Number actualNumber && expected instanceof Number expectedNumber) {
			return Long.compare(actualNumber.longValue(), expectedNumber.longValue());
		}
		if (actual instanceof Boolean actualBoolean && expected instanceof Boolean expectedBoolean) {
			return Boolean.compare(actualBoolean, expectedBoolean);
		}
		return String.valueOf(actual).compareTo(String.valueOf(expected));
	}

	private record Literal(Object value) {
	}

	private interface PredicateValue {
		Object evaluate(SqlRow row, EvaluationContext context);
	}

	private record LiteralPredicateValue(Literal literal) implements PredicateValue {
		@Override
		public Object evaluate(SqlRow row, EvaluationContext context) {
			return literal.value();
		}
	}

	private record ExpressionPredicateValue(ValueExpression expression) implements PredicateValue {
		@Override
		public Object evaluate(SqlRow row, EvaluationContext context) {
			return expression.evaluate(row, context);
		}
	}

	private enum Operator {
		EQUALS,
		NOT_EQUALS,
		LESS_THAN,
		LESS_THAN_OR_EQUAL,
		GREATER_THAN,
		GREATER_THAN_OR_EQUAL,
		LIKE,
		NOT_LIKE
	}

	private record ComparableValue(Object value) implements Comparable<ComparableValue> {
		static ComparableValue from(Object value) {
			return new ComparableValue(value);
		}

		@Override
		public int compareTo(ComparableValue other) {
			if (value == null && other.value == null) {
				return 0;
			}
			if (value == null) {
				return 1;
			}
			if (other.value == null) {
				return -1;
			}
			if (value instanceof Number left && other.value instanceof Number right) {
				return Long.compare(left.longValue(), right.longValue());
			}
			if (value instanceof AddressValue left && other.value instanceof AddressValue right) {
				return Long.compareUnsigned(left.offset(), right.offset());
			}
			if (value instanceof Boolean left && other.value instanceof Boolean right) {
				return Boolean.compare(left, right);
			}
			return String.valueOf(value).compareTo(String.valueOf(other.value));
		}
	}

	private final class EvaluationContext {

		private final Program program;
		private final FromClause fromClause;
		private final List<TableBinding> bindings;
		private final Map<String, TableBinding> bindingsByAlias;
		private CallGraphLevelIndex callGraphLevelIndex;
		private DecompInterface decompiler;
		private final Map<Address, String> decompilationCache = new HashMap<>();
		private final Map<Address, String> instructionsCache = new HashMap<>();
		private final Map<String, String> promptCache = new HashMap<>();

		private final SpecterStreamingResponseListener promptListener;

		EvaluationContext(Program program, TableSchema schema) {
			this(program, schema, SpecterStreamingResponseListener.IGNORE);
		}

		EvaluationContext(Program program, TableSchema schema,
				SpecterStreamingResponseListener promptListener) {
			this.program = program;
			this.promptListener =
				Objects.requireNonNullElse(promptListener, SpecterStreamingResponseListener.IGNORE);
			this.fromClause = new FromClause(new TableReference(schema.name(), schema.name()), List.of());
			TableBinding binding = new TableBinding(schema.name(), normalizeIdentifier(schema.name()), schema);
			this.bindings = List.of(binding);
			this.bindingsByAlias = Map.of(binding.alias(), binding);
		}

		EvaluationContext(Program program, FromClause fromClause) {
			this(program, fromClause, SpecterStreamingResponseListener.IGNORE);
		}

		EvaluationContext(Program program, FromClause fromClause,
				SpecterStreamingResponseListener promptListener) {
			this.program = program;
			this.promptListener =
				Objects.requireNonNullElse(promptListener, SpecterStreamingResponseListener.IGNORE);
			this.fromClause = fromClause;
			List<TableBinding> resolvedBindings = new ArrayList<>();
			Map<String, TableBinding> resolvedByAlias = new LinkedHashMap<>();
			if (fromClause != null) {
				addBinding(resolvedBindings, resolvedByAlias, fromClause.base());
				for (JoinClause join : fromClause.joins()) {
					addBinding(resolvedBindings, resolvedByAlias, join.table());
				}
			}
			this.bindings = List.copyOf(resolvedBindings);
			this.bindingsByAlias = Map.copyOf(resolvedByAlias);
		}

		private void addBinding(List<TableBinding> bindings,
				Map<String, TableBinding> bindingsByAlias, TableReference tableReference) {
			TableSchema schema = requireTable(tableReference.tableName());
			TableBinding binding =
				new TableBinding(schema.name(), tableReference.alias(), schema);
			if (bindingsByAlias.putIfAbsent(binding.alias(), binding) != null) {
				throw new IllegalArgumentException(
					"Duplicate table alias '" + binding.alias() + "'.");
			}
			bindings.add(binding);
		}

		TableSchema schema() {
			if (bindings.isEmpty()) {
				throw new IllegalArgumentException("No table is available for this query.");
			}
			return bindings.get(0).schema();
		}

		List<TableBinding> bindings() {
			return bindings;
		}

		boolean joined() {
			return bindings.size() > 1;
		}

		TableBinding requireBinding(String alias) {
			TableBinding binding = bindingsByAlias.get(normalizeIdentifier(alias));
			if (binding == null) {
				throw new IllegalArgumentException("Unknown table alias '" + alias + "'.");
			}
			return binding;
		}

		boolean hasTable(String tableName) {
			String normalizedTableName = tableName.toUpperCase(Locale.ROOT);
			for (TableBinding binding : bindings) {
				if (binding.tableName().equals(normalizedTableName)) {
					return true;
				}
			}
			return false;
		}

		Object columnValue(SqlRow row, String qualifier, String columnName) {
			TableBinding binding = qualifier == null ?
				resolveUnqualifiedBinding(columnName) : resolveQualifiedBinding(qualifier);
			SqlRow boundRow = rowForBinding(row, binding);
			return requireColumn(binding.schema(), columnName).value(boundRow);
		}

		private TableBinding resolveUnqualifiedBinding(String columnName) {
			TableBinding match = null;
			for (TableBinding binding : bindings) {
				if (binding.schema().columnByName(columnName) == null) {
					continue;
				}
				if (match != null) {
					throw new IllegalArgumentException(
						"Ambiguous column '" + columnName + "'. Use a table alias qualifier.");
				}
				match = binding;
			}
			if (match == null) {
				throw new IllegalArgumentException("Unknown column '" + columnName + "'.");
			}
			return match;
		}

		private TableBinding resolveQualifiedBinding(String qualifier) {
			String normalizedQualifier = normalizeIdentifier(qualifier);
			TableBinding aliasMatch = bindingsByAlias.get(normalizedQualifier);
			if (aliasMatch != null) {
				return aliasMatch;
			}

			TableBinding tableMatch = null;
			for (TableBinding binding : bindings) {
				if (!normalizeIdentifier(binding.tableName()).equals(normalizedQualifier)) {
					continue;
				}
				if (tableMatch != null) {
					throw new IllegalArgumentException(
						"Ambiguous table qualifier '" + qualifier + "'. Use a table alias.");
				}
				tableMatch = binding;
			}
			if (tableMatch == null) {
				throw new IllegalArgumentException("Unknown table qualifier '" + qualifier + "'.");
			}
			return tableMatch;
		}

		private SqlRow rowForBinding(SqlRow row, TableBinding binding) {
			if (row instanceof JoinedRow joinedRow) {
				return joinedRow.rowForAlias(binding.alias());
			}
			if (bindings.size() == 1 && bindings.get(0).alias().equals(binding.alias())) {
				return row;
			}
			throw new IllegalArgumentException(
				"No row is available for table alias '" + binding.alias() + "'.");
		}

		Integer callGraphLevel(AddressValue addressValue) {
			if (callGraphLevelIndex == null) {
				callGraphLevelIndex = CallGraphLevelIndex.build(program);
			}
			return callGraphLevelIndex.level(addressValue.address());
		}

		String decompilation(AddressValue addressValue) {
			String cachedDecompilation = decompilationCache.get(addressValue.address());
			if (cachedDecompilation != null) {
				return cachedDecompilation;
			}
			String decompilation = decompile(addressValue);
			decompilationCache.put(addressValue.address(), decompilation);
			return decompilation;
		}

		String instructions(AddressValue addressValue) {
			String cachedInstructions = instructionsCache.get(addressValue.address());
			if (cachedInstructions != null) {
				return cachedInstructions;
			}
			String instructions = collectInstructions(addressValue);
			instructionsCache.put(addressValue.address(), instructions);
			return instructions;
		}

		String prompt(String prompt, SqlRow row) {
			String promptWithContext = appendRowContext(prompt, row);
			return promptCache.computeIfAbsent(promptWithContext,
				value -> promptInvoker.invoke(value, promptListener));
		}

		private String appendRowContext(String prompt, SqlRow row) {
			if (row == null || row instanceof SyntheticRow || bindings.isEmpty()) {
				return prompt;
			}

			StringBuilder builder = new StringBuilder(prompt.strip());
			builder.append("\n\nSQL row context for this prompt() evaluation:\n");
			for (TableBinding binding : bindings) {
				SqlRow boundRow = rowForBinding(row, binding);
				builder.append(binding.tableName());
				if (!normalizeIdentifier(binding.tableName()).equals(binding.alias())) {
					builder.append(" AS ").append(binding.alias());
				}
				builder.append(":\n");
				for (Column column : binding.schema().columns()) {
					builder.append("- ")
							.append(column.name())
							.append(" = ")
							.append(formatPromptContextValue(column.value(boundRow)))
							.append('\n');
				}
			}
			return builder.toString();
		}

		private String collectInstructions(AddressValue addressValue) {
			ghidra.program.model.listing.Function function =
				program.getFunctionManager().getFunctionContaining(addressValue.address());
			if (function == null) {
				throw new IllegalStateException("No function contains address " + addressValue + ".");
			}

			InstructionIterator iterator =
				program.getListing().getInstructions(function.getBody(), true);
			StringBuilder builder = new StringBuilder();
			while (iterator.hasNext()) {
				Instruction instruction = iterator.next();
				builder.append(instruction.getAddress())
						.append("  ")
						.append(instruction)
						.append('\n');
			}
			if (builder.isEmpty()) {
				return "No instructions found for function " + function.getName() + ".";
			}
			return builder.toString().stripTrailing();
		}

		private String decompile(AddressValue addressValue) {
			ghidra.program.model.listing.Function function =
				program.getFunctionManager().getFunctionContaining(addressValue.address());
			if (function == null) {
				throw new IllegalStateException("No function contains address " + addressValue + ".");
			}

			DecompileResults results =
				decompiler().decompileFunction(function, DECOMPILATION_TIMEOUT_SECONDS,
					TaskMonitor.DUMMY);
			if (!results.decompileCompleted()) {
				throw new IllegalStateException(buildDecompilationFailureMessage(results, function));
			}

			DecompiledFunction decompiledFunction = results.getDecompiledFunction();
			if (decompiledFunction == null || decompiledFunction.getC() == null ||
				decompiledFunction.getC().isBlank()) {
				throw new IllegalStateException(
					"Decompiler returned no C output for function " + function.getName() + ".");
			}
			return decompiledFunction.getC();
		}

		private DecompInterface decompiler() {
			if (decompiler == null) {
				decompiler = new DecompInterface();
				if (!decompiler.openProgram(program)) {
					throw new IllegalStateException(
						"Unable to open the current program in the decompiler.");
				}
			}
			return decompiler;
		}

		void dispose() {
			if (decompiler != null) {
				decompiler.dispose();
			}
		}
	}

	private static String buildDecompilationFailureMessage(DecompileResults results,
			ghidra.program.model.listing.Function function) {
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

	private static final class CallGraphLevelIndex {

		private final Map<Address, Integer> levels;

		private CallGraphLevelIndex(Map<Address, Integer> levels) {
			this.levels = levels;
		}

		static CallGraphLevelIndex build(Program program) {
			try {
				AbstractDependencyGraph<Address> graph =
					new AcyclicCallGraphBuilder(program, true)
							.getDependencyGraph(TaskMonitor.DUMMY);
				return new CallGraphLevelIndex(computeRootBasedLevels(program, graph));
			}
			catch (CancelledException e) {
				throw new IllegalStateException("Callgraph level computation was cancelled.", e);
			}
		}

		private static Map<Address, Integer> computeRootBasedLevels(Program program,
				AbstractDependencyGraph<Address> graph) {
			Set<Address> functions = graph.getValues();
			Map<Address, Set<Address>> callerToCallees = new HashMap<>();
			Set<Address> calledFunctions = new HashSet<>();

			for (Address callee : functions) {
				for (Address caller : graph.getDependentValues(callee)) {
					callerToCallees.computeIfAbsent(caller, ignored -> new HashSet<>()).add(callee);
					calledFunctions.add(callee);
				}
			}

			Map<Address, Integer> levels = new HashMap<>();
			Queue<Address> pending = new LinkedList<>();
			for (Address address : functions) {
				if (!calledFunctions.contains(address) || isStartFunction(program, address)) {
					levels.put(address, 0);
					pending.add(address);
				}
			}

			if (pending.isEmpty()) {
				for (Address address : functions) {
					levels.put(address, 0);
					pending.add(address);
				}
			}

			while (!pending.isEmpty()) {
				Address caller = pending.remove();
				int nextLevel = levels.get(caller) + 1;
				for (Address callee : callerToCallees.getOrDefault(caller, Set.of())) {
					Integer currentLevel = levels.get(callee);
					if (currentLevel == null || nextLevel > currentLevel) {
						levels.put(callee, nextLevel);
						pending.add(callee);
					}
				}
			}

			return levels;
		}

		private static boolean isStartFunction(Program program, Address address) {
			ReferenceManager referenceManager = program.getReferenceManager();
			Iterable<Reference> referencesTo = referenceManager.getReferencesTo(address);
			for (Reference reference : referencesTo) {
				if (reference.isEntryPointReference()) {
					return true;
				}
				if (reference.getReferenceType().isCall()) {
					return false;
				}
			}
			return true;
		}

		Integer level(Address address) {
			return levels.get(address);
		}
	}

	private static final class Parser {

		private final List<Token> tokens;
		private int index;

		Parser(String queryText) {
			tokens = new Tokenizer(queryText).tokenize();
		}

		SqlStatement parse() {
			if (tokens.isEmpty()) {
				throw new IllegalArgumentException("SQL query is empty.");
			}
			if (matchKeyword("SELECT")) {
				return parseSelectStatement();
			}
			if (matchKeyword("UPDATE")) {
				return parseUpdateStatement();
			}
			throw new IllegalArgumentException("Expected SELECT or UPDATE.");
		}

		private Query parseSelectStatement() {
			boolean unique = matchKeyword("UNIQUE") || matchKeyword("DISTINCT");
			List<ValueExpression> expressions = parseSelectExpressions();
			FromClause fromClause = matchKeyword("FROM") ? parseFromClause() : null;
			Condition where = null;
			List<ValueExpression> groupBy = List.of();
			OrderBy orderBy = null;
			Integer limit = null;

			if (matchKeyword("WHERE")) {
				if (fromClause == null) {
					throw new IllegalArgumentException("WHERE requires a FROM clause.");
				}
				where = parseCondition();
			}
			if (matchKeyword("GROUP")) {
				if (fromClause == null) {
					throw new IllegalArgumentException("GROUP BY requires a FROM clause.");
				}
				requireKeyword("BY");
				groupBy = parseGroupByExpressions(expressions);
			}
			if (matchKeyword("ORDER")) {
				requireKeyword("BY");
				ValueExpression expression = parseExpression();
				if (expression.isAggregate()) {
					throw new IllegalArgumentException("Aggregate expressions are not supported in ORDER BY.");
				}
				String blockFunctionName = expression.blockOutputFunctionName();
				if (blockFunctionName != null) {
					throw new IllegalArgumentException(blockFunctionName +
						" is only supported in the SELECT list.");
				}
				boolean ascending = true;
				if (matchKeyword("ASC")) {
					ascending = true;
				}
				else if (matchKeyword("DESC")) {
					ascending = false;
				}
				orderBy = new OrderBy(expression, ascending);
			}
			if (matchKeyword("LIMIT")) {
				limit = parseLimit();
			}
			matchSymbol(";");
			if (!isAtEnd()) {
				throw new IllegalArgumentException("Unsupported SQL after '" + peek().text() + "'.");
			}
			return new Query(expressions, fromClause, unique, where, groupBy,
				orderBy, limit);
		}

		private FromClause parseFromClause() {
			TableReference base = parseTableReference();
			List<JoinClause> joins = new ArrayList<>();
			while (matchKeyword("JOIN")) {
				TableReference table = parseTableReference();
				requireKeyword("ON");
				joins.add(new JoinClause(table, parseCondition()));
			}
			return new FromClause(base, joins);
		}

		private TableReference parseTableReference() {
			String tableName = requireIdentifier("table name");
			String alias = null;
			if (matchKeyword("AS")) {
				alias = requireIdentifier("table alias");
			}
			else if (!isAtEnd() && peek().kind() == TokenKind.IDENTIFIER &&
				!isTableReferenceTerminator(peek().text())) {
				alias = peek().text();
				index++;
			}
			return new TableReference(tableName, alias == null ? tableName : alias);
		}

		private UpdateStatement parseUpdateStatement() {
			String tableName = requireIdentifier("table name");
			requireKeyword("SET");
			String columnName = requireIdentifier("column name");
			requireSymbol("=");
			ValueExpression value = parseExpression();
			if (value.isAggregate()) {
				throw new IllegalArgumentException("Aggregate expressions are not supported in UPDATE.");
			}
			String blockFunctionName = value.blockOutputFunctionName();
			if (blockFunctionName != null && !PROMPT_FUNCTION.equals(blockFunctionName)) {
				throw new IllegalArgumentException(blockFunctionName +
					" is not supported in UPDATE.");
			}
			requireKeyword("WHERE");
			Condition where = parseCondition();
			matchSymbol(";");
			if (!isAtEnd()) {
				throw new IllegalArgumentException("Unsupported SQL after '" + peek().text() + "'.");
			}
			return new UpdateStatement(tableName.toUpperCase(Locale.ROOT), columnName, value, where);
		}

		private List<ValueExpression> parseSelectExpressions() {
			if (matchSymbol("*")) {
				return List.of(new StarExpression());
			}

			List<ValueExpression> expressions = new ArrayList<>();
			do {
				expressions.add(parseSelectExpression());
			}
			while (matchSymbol(","));
			return List.copyOf(expressions);
		}

		private ValueExpression parseSelectExpression() {
			ValueExpression expression = parseExpression();
			String alias = parseOptionalAlias();
			return alias == null ? expression : new AliasedExpression(expression, alias);
		}

		private String parseOptionalAlias() {
			if (matchKeyword("AS")) {
				return requireIdentifier("column alias");
			}
			if (isAtEnd() || peek().kind() != TokenKind.IDENTIFIER) {
				return null;
			}
			String candidate = peek().text();
			if (isSelectTerminator(candidate)) {
				return null;
			}
			index++;
			return candidate;
		}

		private static boolean isSelectTerminator(String identifier) {
			return "FROM".equalsIgnoreCase(identifier);
		}

		private static boolean isTableReferenceTerminator(String identifier) {
			return "JOIN".equalsIgnoreCase(identifier) ||
				"ON".equalsIgnoreCase(identifier) ||
				"WHERE".equalsIgnoreCase(identifier) ||
				"GROUP".equalsIgnoreCase(identifier) ||
				"ORDER".equalsIgnoreCase(identifier) ||
				"LIMIT".equalsIgnoreCase(identifier);
		}

		private List<ValueExpression> parseGroupByExpressions(List<ValueExpression> selectExpressions) {
			List<ValueExpression> expressions = new ArrayList<>();
			do {
				expressions.add(parseGroupByExpression(selectExpressions));
			}
			while (matchSymbol(","));
			return List.copyOf(expressions);
		}

		private ValueExpression parseGroupByExpression(List<ValueExpression> selectExpressions) {
			ValueExpression aliasedExpression = matchSelectExpressionAlias(selectExpressions);
			if (aliasedExpression != null) {
				return aliasedExpression;
			}
			ValueExpression expression = parseExpression();
			if (expression.isAggregate()) {
				throw new IllegalArgumentException("Aggregate expressions are not supported in GROUP BY.");
			}
			String blockFunctionName = expression.blockOutputFunctionName();
			if (blockFunctionName != null) {
				throw new IllegalArgumentException(blockFunctionName + " is not supported in GROUP BY.");
			}
			return expression;
		}

		private ValueExpression matchSelectExpressionAlias(List<ValueExpression> selectExpressions) {
			if (isAtEnd() || peek().kind() != TokenKind.IDENTIFIER || isNextSymbol("(")) {
				return null;
			}
			String alias = peek().text();
			for (ValueExpression expression : selectExpressions) {
				if (normalizeIdentifier(expression.label()).equals(normalizeIdentifier(alias))) {
					index++;
					return expression;
				}
			}
			return null;
		}

		private ValueExpression parseExpression() {
			if (isAtEnd()) {
				throw new IllegalArgumentException("Expected expression.");
			}
			Token token = peek();
			if (isLiteralToken(token)) {
				index++;
				return new LiteralExpression(parseLiteralToken(token));
			}
			String identifier = requireIdentifier("expression");
			if (matchSymbol("(")) {
				String normalizedIdentifier = normalizeIdentifier(identifier);
				if (COUNT_FUNCTION.equals(normalizedIdentifier)) {
					CountArgument argument = parseCountArgument();
					String blockFunctionName = argument.blockOutputFunctionName();
					if (blockFunctionName != null) {
						throw new IllegalArgumentException(blockFunctionName +
							" is not supported inside " + COUNT_FUNCTION + "().");
					}
					if (matchSymbol(",")) {
						throw new IllegalArgumentException("SQL function '" + identifier +
							"' expects exactly one argument.");
					}
					requireSymbol(")");
					return new CountExpression(argument);
				}
				if (!CALLGRAPH_LEVEL_FUNCTION.equals(normalizedIdentifier) &&
					!CONCAT_FUNCTION.equals(normalizedIdentifier) &&
					!DECOMPILATION_FUNCTION.equals(normalizedIdentifier) &&
					!INSTRUCTIONS_FUNCTION.equals(normalizedIdentifier) &&
					!PROMPT_FUNCTION.equals(normalizedIdentifier)) {
					throw new IllegalArgumentException("Unsupported SQL function '" + identifier + "'.");
				}
				List<ValueExpression> arguments = parseFunctionArguments(identifier);
				if (CONCAT_FUNCTION.equals(normalizedIdentifier)) {
					if (arguments.size() < 2) {
						throw new IllegalArgumentException("SQL function '" + identifier +
							"' expects at least two arguments.");
					}
				}
				else if (arguments.size() != 1) {
					throw new IllegalArgumentException("SQL function '" + identifier +
						"' expects exactly one argument.");
				}
				return new FunctionCallExpression(identifier, arguments);
			}
			if (matchSymbol(".")) {
				return new ColumnExpression(identifier, requireIdentifier("column name"));
			}
			return new ColumnExpression(identifier);
		}

		private List<ValueExpression> parseFunctionArguments(String functionName) {
			if (matchSymbol(")")) {
				throw new IllegalArgumentException("SQL function '" + functionName +
					"' expects at least one argument.");
			}
			List<ValueExpression> arguments = new ArrayList<>();
			do {
				arguments.add(parseExpression());
			}
			while (matchSymbol(","));
			requireSymbol(")");
			return List.copyOf(arguments);
		}

		private CountArgument parseCountArgument() {
			if (matchSymbol("*")) {
				return new CountAllArgument();
			}
			if (isAtEnd()) {
				throw new IllegalArgumentException("Expected COUNT argument.");
			}
			Token token = peek();
			if (isLiteralToken(token)) {
				index++;
				return new LiteralCountArgument(parseLiteralToken(token));
			}
			ValueExpression expression = parseExpression();
			if (expression.isAggregate()) {
				throw new IllegalArgumentException("Nested aggregate expressions are not supported.");
			}
			return new ExpressionCountArgument(expression);
		}

		private Condition parseCondition() {
			return parseOrCondition();
		}

		private Condition parseOrCondition() {
			Condition condition = parseAndCondition();
			while (matchKeyword("OR")) {
				condition = new OrCondition(condition, parseAndCondition());
			}
			return condition;
		}

		private Condition parseAndCondition() {
			Condition condition = parseConditionPrimary();
			while (matchKeyword("AND")) {
				condition = new AndCondition(condition, parseConditionPrimary());
			}
			return condition;
		}

		private Condition parseConditionPrimary() {
			if (matchSymbol("(")) {
				Condition condition = parseOrCondition();
				requireSymbol(")");
				return condition;
			}
			return parsePredicateCondition();
		}

		private Condition parsePredicateCondition() {
			ValueExpression expression = parseExpression();
			if (expression.isAggregate()) {
				throw new IllegalArgumentException("Aggregate expressions are not supported in WHERE.");
			}
			String blockFunctionName = expression.blockOutputFunctionName();
			if (blockFunctionName != null) {
				throw new IllegalArgumentException(blockFunctionName +
					" is only supported in the SELECT list.");
			}
			if (matchKeyword("BETWEEN")) {
				PredicateValue lower = parsePredicateValue();
				requireKeyword("AND");
				PredicateValue upper = parsePredicateValue();
				return new BetweenCondition(expression, lower, upper);
			}
			if (matchKeyword("IN")) {
				return new InCondition(expression, parseInValues(), false);
			}
			if (matchKeyword("NOT")) {
				if (matchKeyword("IN")) {
					return new InCondition(expression, parseInValues(), true);
				}
				if (matchKeyword("LIKE")) {
					PredicateValue expected = parsePredicateValue();
					return new PredicateCondition(expression, Operator.NOT_LIKE, expected);
				}
				throw new IllegalArgumentException("Expected IN or LIKE after NOT.");
			}
			Operator operator = parseOperator();
			PredicateValue expected = parsePredicateValue();
			return new PredicateCondition(expression, operator, expected);
		}

		private List<PredicateValue> parseInValues() {
			requireSymbol("(");
			if (matchSymbol(")")) {
				throw new IllegalArgumentException("IN requires at least one value.");
			}
			List<PredicateValue> values = new ArrayList<>();
			do {
				values.add(parsePredicateValue());
			}
			while (matchSymbol(","));
			requireSymbol(")");
			return List.copyOf(values);
		}

		private PredicateValue parsePredicateValue() {
			if (isAtEnd()) {
				throw new IllegalArgumentException("Expected predicate value.");
			}
			Token token = peek();
			if (isLiteralToken(token)) {
				index++;
				return new LiteralPredicateValue(parseLiteralToken(token));
			}
			return new ExpressionPredicateValue(parseExpression());
		}

		private static boolean isLiteralToken(Token token) {
			return token.kind() == TokenKind.STRING || token.kind() == TokenKind.NUMBER ||
				isKeywordLiteral(token);
		}

		private static boolean isKeywordLiteral(Token token) {
			return token.kind() == TokenKind.IDENTIFIER &&
				("true".equalsIgnoreCase(token.text()) ||
					"false".equalsIgnoreCase(token.text()) ||
					"null".equalsIgnoreCase(token.text()));
		}

		private Operator parseOperator() {
			if (matchSymbol("=")) {
				return Operator.EQUALS;
			}
			if (matchSymbol("!=") || matchSymbol("<>")) {
				return Operator.NOT_EQUALS;
			}
			if (matchSymbol("<=")) {
				return Operator.LESS_THAN_OR_EQUAL;
			}
			if (matchSymbol("<")) {
				return Operator.LESS_THAN;
			}
			if (matchSymbol(">=")) {
				return Operator.GREATER_THAN_OR_EQUAL;
			}
			if (matchSymbol(">")) {
				return Operator.GREATER_THAN;
			}
			if (matchKeyword("LIKE")) {
				return Operator.LIKE;
			}
			throw new IllegalArgumentException("Expected WHERE operator.");
		}

		private Literal parseLiteral() {
			Token token = requireToken("literal");
			return parseLiteralToken(token);
		}

		private Literal parseLiteralToken(Token token) {
			return switch (token.kind()) {
				case STRING -> new Literal(token.text());
				case NUMBER -> new Literal(parseLong(token.text(), "numeric literal"));
				case IDENTIFIER -> {
					if ("true".equalsIgnoreCase(token.text())) {
						yield new Literal(true);
					}
					if ("false".equalsIgnoreCase(token.text())) {
						yield new Literal(false);
					}
					if ("null".equalsIgnoreCase(token.text())) {
						yield new Literal(null);
					}
					throw new IllegalArgumentException("Expected quoted string, number, boolean, or NULL literal.");
				}
				case SYMBOL -> throw new IllegalArgumentException(
					"Expected quoted string, number, boolean, or NULL literal.");
			};
		}

		private int parseLimit() {
			Token token = requireToken("LIMIT value");
			if (token.kind() != TokenKind.NUMBER) {
				throw new IllegalArgumentException("LIMIT must be a positive integer.");
			}
			long parsed = parseLong(token.text(), "LIMIT");
			if (parsed <= 0 || parsed > Integer.MAX_VALUE) {
				throw new IllegalArgumentException("LIMIT must be a positive integer.");
			}
			return (int) parsed;
		}

		private long parseLong(String value, String label) {
			try {
				if (value.startsWith("0x") || value.startsWith("0X")) {
					return Long.parseUnsignedLong(value.substring(2), 16);
				}
				return Long.parseLong(value);
			}
			catch (NumberFormatException e) {
				throw new IllegalArgumentException(label + " is out of range.", e);
			}
		}

		private void requireKeyword(String keyword) {
			if (!matchKeyword(keyword)) {
				throw new IllegalArgumentException("Expected " + keyword + ".");
			}
		}

		private void requireSymbol(String symbol) {
			if (!matchSymbol(symbol)) {
				throw new IllegalArgumentException("Expected '" + symbol + "'.");
			}
		}

		private boolean matchKeyword(String keyword) {
			if (isAtEnd()) {
				return false;
			}
			Token token = peek();
			if (token.kind() == TokenKind.IDENTIFIER && keyword.equalsIgnoreCase(token.text())) {
				index++;
				return true;
			}
			return false;
		}

		private String requireIdentifier(String label) {
			Token token = requireToken(label);
			if (token.kind() != TokenKind.IDENTIFIER) {
				throw new IllegalArgumentException("Expected " + label + ".");
			}
			return token.text();
		}

		private boolean matchSymbol(String symbol) {
			if (!isAtEnd() && peek().kind() == TokenKind.SYMBOL && symbol.equals(peek().text())) {
				index++;
				return true;
			}
			return false;
		}

		private boolean isNextSymbol(String symbol) {
			int nextIndex = index + 1;
			return nextIndex < tokens.size() && tokens.get(nextIndex).kind() == TokenKind.SYMBOL &&
				symbol.equals(tokens.get(nextIndex).text());
		}

		private Token requireToken(String label) {
			if (isAtEnd()) {
				throw new IllegalArgumentException("Expected " + label + ".");
			}
			return tokens.get(index++);
		}

		private Token peek() {
			return tokens.get(index);
		}

		private boolean isAtEnd() {
			return index >= tokens.size();
		}
	}

	private static final class Tokenizer {

		private final String input;
		private int index;

		Tokenizer(String input) {
			this.input = input == null ? "" : input.strip();
		}

		List<Token> tokenize() {
			List<Token> tokens = new ArrayList<>();
			while (!isAtEnd()) {
				char c = peek();
				if (Character.isWhitespace(c)) {
					index++;
				}
				else if (isIdentifierStart(c)) {
					tokens.add(readIdentifier());
				}
				else if (Character.isDigit(c)) {
					tokens.add(readNumber());
				}
				else if (c == '\'' || c == '"') {
					tokens.add(readString(c));
				}
				else {
					tokens.add(readSymbol());
				}
			}
			return tokens;
		}

		private Token readIdentifier() {
			int start = index++;
			while (!isAtEnd() && isIdentifierPart(peek())) {
				index++;
			}
			return new Token(TokenKind.IDENTIFIER, input.substring(start, index));
		}

		private Token readNumber() {
			int start = index++;
			if (!isAtEnd() && input.charAt(start) == '0' &&
				(peek() == 'x' || peek() == 'X')) {
				index++;
				int hexStart = index;
				while (!isAtEnd() && isHexDigit(peek())) {
					index++;
				}
				if (index == hexStart) {
					throw new IllegalArgumentException("Hex literal requires at least one digit.");
				}
				return new Token(TokenKind.NUMBER, input.substring(start, index));
			}
			while (!isAtEnd() && Character.isDigit(peek())) {
				index++;
			}
			return new Token(TokenKind.NUMBER, input.substring(start, index));
		}

		private Token readString(char quote) {
			StringBuilder builder = new StringBuilder();
			index++;
			while (!isAtEnd()) {
				char c = input.charAt(index++);
				if (c == quote) {
					if (!isAtEnd() && peek() == quote) {
						builder.append(quote);
						index++;
						continue;
					}
					return new Token(TokenKind.STRING, builder.toString());
				}
				builder.append(c);
			}
			throw new IllegalArgumentException("Unterminated string literal.");
		}

		private Token readSymbol() {
			char c = input.charAt(index++);
			if (!isAtEnd()) {
				char next = peek();
				String two = "" + c + next;
				if ("!=".equals(two) || "<=".equals(two) || ">=".equals(two) || "<>".equals(two)) {
					index++;
					return new Token(TokenKind.SYMBOL, two);
				}
			}
			if ("*,;=<>().".indexOf(c) >= 0) {
				return new Token(TokenKind.SYMBOL, String.valueOf(c));
			}
			throw new IllegalArgumentException("Unexpected character '" + c + "'.");
		}

		private boolean isAtEnd() {
			return index >= input.length();
		}

		private char peek() {
			return input.charAt(index);
		}

		private static boolean isIdentifierStart(char c) {
			return Character.isLetter(c) || c == '_';
		}

		private static boolean isIdentifierPart(char c) {
			return Character.isLetterOrDigit(c) || c == '_';
		}

		private static boolean isHexDigit(char c) {
			return Character.digit(c, 16) >= 0;
		}
	}

	private record AddressValue(String text, long offset, Address address) {
		AddressValue(Address address) {
			this(String.valueOf(address), address.getOffset(), address);
		}

		@Override
		public String toString() {
			return text;
		}
	}

	private record Token(TokenKind kind, String text) {
	}

	private enum TokenKind {
		IDENTIFIER,
		NUMBER,
		STRING,
		SYMBOL
	}
}
