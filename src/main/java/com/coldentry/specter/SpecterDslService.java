package com.coldentry.specter;

import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class SpecterDslService {

	private static final int MAX_RENDERED_LENGTH = 64_000;
	private static final Pattern FOR_LOOP_PATTERN = Pattern.compile(
		"(?is)^\\s*FOR\\s+([A-Za-z_][A-Za-z0-9_]*)\\s+IN\\s+(.+?)\\s*;\\s*DO\\s+(.+?)\\s*;?\\s*END\\s*;\\s*$");

	private final SpecterSqlQueryService sqlQueryService;

	SpecterDslService(SpecterSqlQueryService sqlQueryService) {
		this.sqlQueryService = sqlQueryService;
	}

	String help() {
		StringBuilder builder = new StringBuilder();
		builder.append("Usage: enter <SQL | FOR loop> at the specter dsl> prompt.\n");
		builder.append("Press Ctrl+M to switch between DSL and chat modes.\n");
		builder.append('\n');
		builder.append("SQL-like statements:\n");
		builder.append(sqlQueryService.schemaHelp());
		builder.append("\n\nFOR loop:\n");
		builder.append("  FOR level IN SELECT callgraph_level(entry) FROM FUNCTION ")
				.append("ORDER BY callgraph_level(entry) DESC LIMIT 2; DO SELECT entry, name ")
				.append("FROM FUNCTION WHERE callgraph_level(entry) = :level LIMIT 5; END;\n");
		return builder.toString();
	}

	String execute(String scriptText) {
		return execute(scriptText, WriteApproval.ALLOW);
	}

	String execute(String scriptText, WriteApproval writeApproval) {
		return execute(scriptText, writeApproval, SpecterStreamingResponseListener.IGNORE);
	}

	String execute(String scriptText, WriteApproval writeApproval,
			SpecterStreamingResponseListener listener) {
		if (scriptText == null || scriptText.isBlank()) {
			return help();
		}

		String script = scriptText.strip();
		if (startsWithKeyword(script, "FOR")) {
			return executeForLoop(script, writeApproval, listener);
		}
		if (sqlQueryService.isWriteStatement(script)) {
			writeApproval.approve(writeSummary(script));
		}
		return sqlQueryService.execute(script, listener);
	}

	private String executeForLoop(String script, WriteApproval writeApproval,
			SpecterStreamingResponseListener listener) {
        return "Not implemented.";
	}

	private ForLoop parseForLoop(String script) {
		Matcher matcher = FOR_LOOP_PATTERN.matcher(script);
		if (!matcher.matches()) {
			throw new IllegalArgumentException(
				"Expected: FOR <var> IN <sql>; DO <sql>; END;");
		}
		return new ForLoop(matcher.group(1), matcher.group(2).strip(), matcher.group(3).strip());
	}

	private static String substituteVariable(String sql, String variableName, String literal) {
		Pattern variablePattern =
			Pattern.compile(":" + Pattern.quote(variableName) + "\\b", Pattern.CASE_INSENSITIVE);
		return variablePattern.matcher(sql).replaceAll(Matcher.quoteReplacement(literal));
	}

	private static boolean startsWithKeyword(String text, String keyword) {
		String upperText = text.toUpperCase(Locale.ROOT);
		String upperKeyword = keyword.toUpperCase(Locale.ROOT);
		return upperText.equals(upperKeyword) || upperText.startsWith(upperKeyword + " ");
	}

	private static String writeSummary(String script) {
		return "Run Specter DSL database write statement:\n\n" + script;
	}

	@FunctionalInterface
	interface WriteApproval {
		WriteApproval ALLOW = summary -> {
		};

		void approve(String changeSummary);
	}

	private record ForLoop(String variableName, String selectorSql, String bodySql) {
	}
}
