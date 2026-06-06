package com.coldentry.specter;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

final class SpecterSubAgentConfigurationDialog extends JDialog {

	private final DefaultListModel<SubAgentDraft> listModel = new DefaultListModel<>();
	private final JList<SubAgentDraft> agentList = new JList<>(listModel);
	private final JTextField nameField = new JTextField();
	private final JTextField descriptionField = new JTextField();
	private final JTextArea instructionsArea = new JTextArea();
	private boolean updatingFields;
	private boolean confirmed;

	private SpecterSubAgentConfigurationDialog(Window owner,
			SpecterSubAgentConfigurationManager.Snapshot snapshot) {
		super(owner, "Sub-Agent Configuration", Dialog.ModalityType.APPLICATION_MODAL);
		buildUi();
		loadSnapshot(snapshot);
	}

	static Result showDialog(Component parent,
			SpecterSubAgentConfigurationManager.Snapshot snapshot) {
		Window owner = parent == null ? null : SwingUtilities.getWindowAncestor(parent);
		SpecterSubAgentConfigurationDialog dialog =
			new SpecterSubAgentConfigurationDialog(owner, snapshot);
		dialog.setLocationRelativeTo(parent);
		dialog.setVisible(true);
		if (!dialog.confirmed) {
			return null;
		}
		return dialog.buildResult();
	}

	private void buildUi() {
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		setLayout(new BorderLayout(8, 8));

		JPanel content = new JPanel(new BorderLayout(8, 8));
		content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		content.add(buildListPanel(), BorderLayout.WEST);
		content.add(buildEditorPanel(), BorderLayout.CENTER);

		add(content, BorderLayout.CENTER);
		add(buildButtonPanel(), BorderLayout.SOUTH);

		setPreferredSize(new Dimension(860, 420));
		pack();
	}

	private Component buildListPanel() {
		JPanel listPanel = new JPanel(new BorderLayout(0, 8));
		listPanel.setBorder(BorderFactory.createTitledBorder("Sub-Agents"));

		agentList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		agentList.addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				loadSelectedDraft();
			}
		});

		JScrollPane listScrollPane = new JScrollPane(agentList);
		listScrollPane.setPreferredSize(new Dimension(280, 250));
		listPanel.add(listScrollPane, BorderLayout.CENTER);

		JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
		JButton addButton = new JButton("Add");
		addButton.addActionListener(e -> addSubAgent());
		JButton removeButton = new JButton("Remove");
		removeButton.addActionListener(e -> removeSelectedSubAgent());
		actions.add(addButton);
		actions.add(removeButton);
		listPanel.add(actions, BorderLayout.SOUTH);
		return listPanel;
	}

	private Component buildEditorPanel() {
		JPanel editorPanel = new JPanel(new GridBagLayout());
		editorPanel.setBorder(BorderFactory.createTitledBorder("Selected Sub-Agent"));

		instructionsArea.setLineWrap(true);
		instructionsArea.setWrapStyleWord(true);
		JScrollPane instructionsScrollPane = new JScrollPane(instructionsArea);
		instructionsScrollPane.setPreferredSize(new Dimension(440, 190));

		GridBagConstraints constraints = new GridBagConstraints();
		constraints.gridx = 0;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.NORTHWEST;
		constraints.fill = GridBagConstraints.HORIZONTAL;
		constraints.weightx = 0;
		constraints.insets = new Insets(6, 6, 6, 6);

		addLabel(editorPanel, constraints, "Name");
		addField(editorPanel, constraints, nameField);
		addLabel(editorPanel, constraints, "Description");
		addField(editorPanel, constraints, descriptionField);

		constraints.gridx = 0;
		constraints.weightx = 0;
		editorPanel.add(new JLabel("Instructions"), constraints);
		constraints.gridx = 1;
		constraints.weightx = 1;
		constraints.weighty = 1;
		constraints.fill = GridBagConstraints.BOTH;
		editorPanel.add(instructionsScrollPane, constraints);

		DocumentListener updateListener = new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				updateDraftFromFields();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				updateDraftFromFields();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				updateDraftFromFields();
			}
		};
		nameField.getDocument().addDocumentListener(updateListener);
		descriptionField.getDocument().addDocumentListener(updateListener);
		instructionsArea.getDocument().addDocumentListener(updateListener);

		return editorPanel;
	}

	private void addLabel(JPanel panel, GridBagConstraints constraints, String text) {
		constraints.gridx = 0;
		constraints.weightx = 0;
		constraints.weighty = 0;
		constraints.fill = GridBagConstraints.HORIZONTAL;
		panel.add(new JLabel(text), constraints);
	}

	private void addField(JPanel panel, GridBagConstraints constraints, Component field) {
		constraints.gridx = 1;
		constraints.weightx = 1;
		constraints.weighty = 0;
		constraints.fill = GridBagConstraints.HORIZONTAL;
		panel.add(field, constraints);
		constraints.gridy++;
	}

	private Component buildButtonPanel() {
		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
		JButton okButton = new JButton("OK");
		okButton.addActionListener(e -> confirmSelection());
		JButton cancelButton = new JButton("Cancel");
		cancelButton.addActionListener(e -> dispose());
		buttonPanel.add(okButton);
		buttonPanel.add(cancelButton);
		getRootPane().setDefaultButton(okButton);
		return buttonPanel;
	}

	private void loadSnapshot(SpecterSubAgentConfigurationManager.Snapshot snapshot) {
		for (SpecterSubAgentDefinition definition : snapshot.definitions()) {
			listModel.addElement(new SubAgentDraft(definition));
		}
		if (!listModel.isEmpty()) {
			agentList.setSelectedIndex(0);
		}
		loadSelectedDraft();
	}

	private void addSubAgent() {
		listModel.addElement(new SubAgentDraft(new SpecterSubAgentDefinition("New Sub-Agent",
			"", "Define what this sub-agent should do.")));
		agentList.setSelectedIndex(listModel.size() - 1);
		nameField.requestFocusInWindow();
		nameField.selectAll();
	}

	private void removeSelectedSubAgent() {
		int selectedIndex = agentList.getSelectedIndex();
		if (selectedIndex < 0) {
			return;
		}
		listModel.remove(selectedIndex);
		if (listModel.isEmpty()) {
			loadSelectedDraft();
			return;
		}
		agentList.setSelectedIndex(Math.min(selectedIndex, listModel.size() - 1));
	}

	private void loadSelectedDraft() {
		SubAgentDraft draft = agentList.getSelectedValue();
		updatingFields = true;
		try {
			boolean hasSelection = draft != null;
			nameField.setEnabled(hasSelection);
			descriptionField.setEnabled(hasSelection);
			instructionsArea.setEnabled(hasSelection);
			nameField.setText(hasSelection ? valueOrEmpty(draft.name) : "");
			descriptionField.setText(hasSelection ? valueOrEmpty(draft.description) : "");
			instructionsArea.setText(hasSelection ? valueOrEmpty(draft.instructions) : "");
		}
		finally {
			updatingFields = false;
		}
	}

	private void updateDraftFromFields() {
		if (updatingFields) {
			return;
		}
		SubAgentDraft draft = agentList.getSelectedValue();
		if (draft == null) {
			return;
		}
		draft.name = normalize(nameField.getText());
		draft.description = normalize(descriptionField.getText());
		draft.instructions = normalize(instructionsArea.getText());
		agentList.repaint();
	}

	private void confirmSelection() {
		List<String> names = new ArrayList<>();
		for (int i = 0; i < listModel.size(); i++) {
			SubAgentDraft draft = listModel.getElementAt(i);
			if (draft.name == null) {
				JOptionPane.showMessageDialog(this, "Each sub-agent needs a name.",
					"Missing Name", JOptionPane.ERROR_MESSAGE);
				return;
			}
			if (draft.instructions == null) {
				JOptionPane.showMessageDialog(this,
					"Sub-agent '" + draft.name + "' needs instructions.",
					"Missing Instructions", JOptionPane.ERROR_MESSAGE);
				return;
			}
			if (containsIgnoreCase(names, draft.name)) {
				JOptionPane.showMessageDialog(this,
					"Sub-agent names must be unique. Duplicate name: " + draft.name,
					"Duplicate Name", JOptionPane.ERROR_MESSAGE);
				return;
			}
			names.add(draft.name);
		}
		confirmed = true;
		dispose();
	}

	private Result buildResult() {
		List<SpecterSubAgentDefinition> definitions = new ArrayList<>(listModel.size());
		for (int i = 0; i < listModel.size(); i++) {
			definitions.add(listModel.getElementAt(i).toDefinition());
		}
		return new Result(definitions);
	}

	private static boolean containsIgnoreCase(List<String> values, String candidate) {
		for (String value : values) {
			if (value.equalsIgnoreCase(candidate)) {
				return true;
			}
		}
		return false;
	}

	private static String valueOrEmpty(String value) {
		return value == null ? "" : value;
	}

	private static String normalize(String value) {
		if (value == null) {
			return null;
		}
		String trimmed = value.trim();
		return trimmed.isEmpty() ? null : trimmed;
	}

	record Result(List<SpecterSubAgentDefinition> definitions) {
		Result {
			definitions = List.copyOf(definitions);
		}
	}

	private static final class SubAgentDraft {

		private String name;
		private String description;
		private String instructions;

		private SubAgentDraft(SpecterSubAgentDefinition definition) {
			name = definition.name();
			description = definition.description();
			instructions = definition.instructions();
		}

		private SpecterSubAgentDefinition toDefinition() {
			return new SpecterSubAgentDefinition(name, description, instructions);
		}

		@Override
		public String toString() {
			if (name == null) {
				return "<unnamed>";
			}
			if (description == null) {
				return name;
			}
			return name + " - " + description;
		}
	}
}
