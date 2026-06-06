package com.coldentry.specter;

import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

final class SpecterDatabaseEditApprovalDialog {

	private SpecterDatabaseEditApprovalDialog() {
		// Utility class.
	}

	static Result showDialog(Component parent, String toolName, String changeSummary) {
		JCheckBox alwaysAllowCheckbox = new JCheckBox(
			"Always allow future " + toolName + " edits without prompting");

		JTextArea summaryArea = new JTextArea(changeSummary);
		summaryArea.setEditable(false);
		summaryArea.setLineWrap(true);
		summaryArea.setWrapStyleWord(true);
		summaryArea.setOpaque(false);
		summaryArea.setBorder(BorderFactory.createEmptyBorder());
		summaryArea.setCaretPosition(0);

		JPanel panel = new JPanel(new BorderLayout(0, 8));
		panel.add(new JLabel("Allow Specter to make this change to the active Ghidra program?"),
			BorderLayout.NORTH);
		panel.add(new JScrollPane(summaryArea), BorderLayout.CENTER);
		panel.add(alwaysAllowCheckbox, BorderLayout.SOUTH);

		int choice = JOptionPane.showConfirmDialog(parent, panel, "Allow Specter Database Edit",
			JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
		return new Result(choice == JOptionPane.YES_OPTION, alwaysAllowCheckbox.isSelected());
	}

	record Result(boolean approved, boolean alwaysAllowFutureRuns) {
	}
}
