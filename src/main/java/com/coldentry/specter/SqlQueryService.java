package com.coldentry.specter;

import java.sql.*;
import java.util.*;
import java.util.function.Supplier;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import org.apache.calcite.jdbc.CalciteConnection;

final class SqlQueryService {

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

	SqlQueryService(Supplier<Program> programSupplier, SpecterPromptInvoker promptInvoker) {
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
        Properties info = new Properties();
        info.setProperty("lex", "JAVA");
        Connection connection = null;
        try {
            connection = DriverManager.getConnection("jdbc:calcite:", info);
        } catch (SQLException e) {
            return e.getMessage();
        }
        CalciteConnection calciteConnection = null;
        try {
            calciteConnection = connection.unwrap(CalciteConnection.class);
        } catch (SQLException e) {
            return e.getMessage();
        }

        var rootSchema = calciteConnection.getRootSchema();
        //var specterSchema = new SpecterSchema(programSupplier.get());
        rootSchema.add("functions", new SpecterFunctionTable(programSupplier.get()));

        Statement stmt = null;
        try {
            stmt = calciteConnection.createStatement();
        } catch (SQLException e) {
            return e.getMessage();
        }

        if (queryText.endsWith(";")) {
            queryText = queryText.substring(0, queryText.length() - 1);
        }

        ResultSet rs = null;
        try {
            rs = stmt.executeQuery(queryText);
            return ResultSetFormatter.formatResultSet(rs);
        } catch (SQLException e) {
            return e.getMessage();
        }
    }

    String execute(String queryText, SpecterStreamingResponseListener listener) {
        return execute(queryText);
    }

	boolean isWriteStatement(String queryText) {
        return false;
	}
}
