package com.coldentry.specter;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class ResultSetFormatter {

    public static String formatResultSet(ResultSet rs) throws SQLException {
        ResultSetMetaData meta = rs.getMetaData();
        int columnCount = meta.getColumnCount();

        List<String[]> rows = new ArrayList<>();
        int[] widths = new int[columnCount];

        // Initialize widths from column labels
        for (int i = 1; i <= columnCount; i++) {
            widths[i - 1] = meta.getColumnLabel(i).length();
        }

        // Read all rows and determine column widths
        while (rs.next()) {
            String[] row = new String[columnCount];

            for (int i = 1; i <= columnCount; i++) {
                Object value = rs.getObject(i);
                String text = value == null ? "NULL" : value.toString();

                row[i - 1] = text;
                widths[i - 1] = Math.max(widths[i - 1], text.length());
            }

            rows.add(row);
        }

        StringBuilder sb = new StringBuilder();

        appendSeparator(sb, widths);

        // Header
        sb.append("|");
        for (int i = 1; i <= columnCount; i++) {
            sb.append(" ")
                    .append(padRight(meta.getColumnLabel(i), widths[i - 1]))
                    .append(" |");
        }
        sb.append('\n');

        appendSeparator(sb, widths);

        // Rows
        for (String[] row : rows) {
            sb.append("|");
            for (int i = 0; i < columnCount; i++) {
                sb.append(" ")
                        .append(padRight(row[i], widths[i]))
                        .append(" |");
            }
            sb.append('\n');
        }

        appendSeparator(sb, widths);
        sb.append(rows.size()).append(" row(s)\n");

        return sb.toString();
    }

    private static void appendSeparator(StringBuilder sb, int[] widths) {
        sb.append("+");
        for (int width : widths) {
            sb.append("-".repeat(width + 2)).append("+");
        }
        sb.append('\n');
    }

    private static String padRight(String value, int width) {
        return String.format("%-" + width + "s", value);
    }
}