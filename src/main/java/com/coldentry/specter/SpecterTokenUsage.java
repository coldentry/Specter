package com.coldentry.specter;

import java.text.NumberFormat;
import java.util.Locale;

final class SpecterTokenUsage {

	private static final NumberFormat INTEGER_FORMAT = NumberFormat.getIntegerInstance(Locale.US);

	private final Integer inputTokens;
	private final Integer outputTokens;
	private final Integer totalTokens;

	private SpecterTokenUsage(Integer inputTokens, Integer outputTokens, Integer totalTokens) {
		this.inputTokens = inputTokens;
		this.outputTokens = outputTokens;
		this.totalTokens = totalTokens;
	}

	static SpecterTokenUsage of(Integer inputTokens, Integer outputTokens, Integer totalTokens) {
		if (inputTokens == null && outputTokens == null && totalTokens == null) {
			return null;
		}
		Integer resolvedTotal = totalTokens;
		if (resolvedTotal == null && inputTokens != null && outputTokens != null) {
			resolvedTotal = inputTokens + outputTokens;
		}
		return new SpecterTokenUsage(inputTokens, outputTokens, resolvedTotal);
	}

	static SpecterTokenUsage sum(SpecterTokenUsage left, SpecterTokenUsage right) {
		if (left == null) {
			return right;
		}
		if (right == null) {
			return left;
		}
		return of(sum(left.inputTokens, right.inputTokens),
			sum(left.outputTokens, right.outputTokens),
			sum(left.totalTokens, right.totalTokens));
	}

	Integer inputTokens() {
		return inputTokens;
	}

	Integer outputTokens() {
		return outputTokens;
	}

	Integer totalTokens() {
		return totalTokens;
	}

	String formatForDisplay() {
		StringBuilder builder = new StringBuilder("Usage:");
		if (inputTokens != null) {
			builder.append(" in ").append(INTEGER_FORMAT.format(inputTokens));
		}
		if (outputTokens != null) {
			builder.append(" out ").append(INTEGER_FORMAT.format(outputTokens));
		}
		if (totalTokens != null) {
			builder.append(" total ").append(INTEGER_FORMAT.format(totalTokens));
		}
		return builder.toString();
	}

	private static Integer sum(Integer left, Integer right) {
		if (left == null) {
			return right;
		}
		if (right == null) {
			return left;
		}
		return left + right;
	}
}
