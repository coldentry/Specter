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
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

final class SpecterModelConfigurationDialog extends JDialog {

	private final DefaultListModel<ModelDraft> listModel = new DefaultListModel<>();
	private final JList<ModelDraft> configurationList = new JList<>(listModel);
	private final JComboBox<SpecterModelProvider> providerComboBox =
		new JComboBox<>(SpecterModelProvider.values());
	private final JTextField endpointField = new JTextField();
	private final JTextField modelField = new JTextField();
	private final JPasswordField apiKeyField = new JPasswordField();
	private final JCheckBox returnThinkingCheckbox = new JCheckBox("Return thinking when supported");
	private final JTextField reasoningEffortField = new JTextField();
	private boolean updatingFields;
	private boolean confirmed;

	private SpecterModelConfigurationDialog(Window owner,
			SpecterModelConfigurationManager.Snapshot snapshot) {
		super(owner, "Model Configuration", Dialog.ModalityType.APPLICATION_MODAL);
		buildUi();
		loadSnapshot(snapshot);
	}

	static Result showDialog(Component parent,
			SpecterModelConfigurationManager.Snapshot snapshot) {
		Window owner = parent == null ? null : SwingUtilities.getWindowAncestor(parent);
		SpecterModelConfigurationDialog dialog =
			new SpecterModelConfigurationDialog(owner, snapshot);
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

		setPreferredSize(new Dimension(780, 360));
		pack();
	}

	private Component buildListPanel() {
		JPanel listPanel = new JPanel(new BorderLayout(0, 8));
		listPanel.setBorder(BorderFactory.createTitledBorder("Configurations"));

		configurationList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		configurationList.addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				loadSelectedDraft();
			}
		});

		JScrollPane listScrollPane = new JScrollPane(configurationList);
		listScrollPane.setPreferredSize(new Dimension(280, 220));
		listPanel.add(listScrollPane, BorderLayout.CENTER);

		JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
		JButton addButton = new JButton("Add");
		addButton.addActionListener(e -> addConfiguration());
		JButton removeButton = new JButton("Remove");
		removeButton.addActionListener(e -> removeSelectedConfiguration());
		actions.add(addButton);
		actions.add(removeButton);
		listPanel.add(actions, BorderLayout.SOUTH);
		return listPanel;
	}

	private Component buildEditorPanel() {
		JPanel editorPanel = new JPanel(new GridBagLayout());
		editorPanel.setBorder(BorderFactory.createTitledBorder("Selected Configuration"));

		GridBagConstraints constraints = new GridBagConstraints();
		constraints.gridx = 0;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.WEST;
		constraints.fill = GridBagConstraints.HORIZONTAL;
		constraints.weightx = 0;
		constraints.insets = new Insets(6, 6, 6, 6);

		addLabel(editorPanel, constraints, "Provider");
		addField(editorPanel, constraints, providerComboBox);
		addLabel(editorPanel, constraints, "Endpoint");
		addField(editorPanel, constraints, endpointField);
		addLabel(editorPanel, constraints, "Model");
		addField(editorPanel, constraints, modelField);
		addLabel(editorPanel, constraints, "API Key");
		addField(editorPanel, constraints, apiKeyField);
		addLabel(editorPanel, constraints, "Reasoning Effort");
		addField(editorPanel, constraints, reasoningEffortField);

		constraints.gridx = 1;
		constraints.gridy++;
		constraints.weightx = 1;
		editorPanel.add(returnThinkingCheckbox, constraints);

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
		endpointField.getDocument().addDocumentListener(updateListener);
		modelField.getDocument().addDocumentListener(updateListener);
		apiKeyField.getDocument().addDocumentListener(updateListener);
		reasoningEffortField.getDocument().addDocumentListener(updateListener);
		providerComboBox.addActionListener(e -> updateDraftFromFields());
		returnThinkingCheckbox.addActionListener(e -> updateDraftFromFields());

		return editorPanel;
	}

	private void addLabel(JPanel panel, GridBagConstraints constraints, String text) {
		constraints.gridx = 0;
		constraints.weightx = 0;
		panel.add(new JLabel(text), constraints);
	}

	private void addField(JPanel panel, GridBagConstraints constraints, Component field) {
		constraints.gridx = 1;
		constraints.weightx = 1;
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

	private void loadSnapshot(SpecterModelConfigurationManager.Snapshot snapshot) {
		for (SpecterOpenAiConfiguration configuration : snapshot.configurations()) {
			listModel.addElement(new ModelDraft(configuration));
		}
		if (listModel.isEmpty()) {
			listModel.addElement(new ModelDraft(SpecterOpenAiConfiguration.defaults()));
		}
		int selectedIndex = Math.max(0, Math.min(snapshot.selectedIndex(), listModel.size() - 1));
		configurationList.setSelectedIndex(selectedIndex);
		loadSelectedDraft();
	}

	private void addConfiguration() {
		listModel.addElement(new ModelDraft(SpecterOpenAiConfiguration.defaults()));
		configurationList.setSelectedIndex(listModel.size() - 1);
		endpointField.requestFocusInWindow();
	}

	private void removeSelectedConfiguration() {
		int selectedIndex = configurationList.getSelectedIndex();
		if (selectedIndex < 0) {
			return;
		}
		listModel.remove(selectedIndex);
		if (listModel.isEmpty()) {
			listModel.addElement(new ModelDraft(SpecterOpenAiConfiguration.defaults()));
			selectedIndex = 0;
		}
		else if (selectedIndex >= listModel.size()) {
			selectedIndex = listModel.size() - 1;
		}
		configurationList.setSelectedIndex(selectedIndex);
	}

	private void loadSelectedDraft() {
		ModelDraft draft = configurationList.getSelectedValue();
		updatingFields = true;
		try {
			boolean hasSelection = draft != null;
			providerComboBox.setEnabled(hasSelection);
			endpointField.setEnabled(hasSelection);
			modelField.setEnabled(hasSelection);
			apiKeyField.setEnabled(hasSelection);
			returnThinkingCheckbox.setEnabled(hasSelection);
			reasoningEffortField.setEnabled(hasSelection);
			providerComboBox.setSelectedItem(
				hasSelection ? draft.provider : SpecterModelProvider.OPENAI_COMPATIBLE);
			endpointField.setText(hasSelection ? valueOrEmpty(draft.baseUrl) : "");
			modelField.setText(hasSelection ? valueOrEmpty(draft.modelName) : "");
			apiKeyField.setText(hasSelection ? valueOrEmpty(draft.apiKey) : "");
			returnThinkingCheckbox.setSelected(hasSelection && Boolean.TRUE.equals(draft.returnThinking));
			reasoningEffortField.setText(hasSelection ? valueOrEmpty(draft.reasoningEffort) : "");
		}
		finally {
			updatingFields = false;
		}
	}

	private void updateDraftFromFields() {
		if (updatingFields) {
			return;
		}
		ModelDraft draft = configurationList.getSelectedValue();
		if (draft == null) {
			return;
		}
		draft.provider = (SpecterModelProvider) providerComboBox.getSelectedItem();
		draft.baseUrl = normalize(endpointField.getText());
		draft.modelName = normalize(modelField.getText());
		draft.apiKey = normalize(new String(apiKeyField.getPassword()));
		draft.returnThinking = returnThinkingCheckbox.isSelected() ? Boolean.TRUE : null;
		draft.reasoningEffort = normalize(reasoningEffortField.getText());
		configurationList.repaint();
	}

	private void confirmSelection() {
		ModelDraft selectedDraft = configurationList.getSelectedValue();
		if (selectedDraft == null) {
			JOptionPane.showMessageDialog(this, "Select a configuration to use.",
				"Missing Selection", JOptionPane.ERROR_MESSAGE);
			return;
		}
		if (selectedDraft.baseUrl == null) {
			JOptionPane.showMessageDialog(this, "The selected configuration needs an endpoint.",
				"Missing Endpoint", JOptionPane.ERROR_MESSAGE);
			return;
		}
		if (selectedDraft.modelName == null) {
			JOptionPane.showMessageDialog(this, "The selected configuration needs a model name.",
				"Missing Model", JOptionPane.ERROR_MESSAGE);
			return;
		}
		confirmed = true;
		dispose();
	}

	private Result buildResult() {
		List<SpecterOpenAiConfiguration> configurations = new ArrayList<>(listModel.size());
		for (int i = 0; i < listModel.size(); i++) {
			configurations.add(listModel.getElementAt(i).toConfiguration());
		}
		return new Result(configurations, configurationList.getSelectedIndex());
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

	record Result(List<SpecterOpenAiConfiguration> configurations, int selectedIndex) {
		Result {
			configurations = List.copyOf(configurations);
		}
	}

	private static final class ModelDraft {

		private SpecterModelProvider provider;
		private String baseUrl;
		private String apiKey;
		private String modelName;
		private Boolean returnThinking;
		private String reasoningEffort;

		private ModelDraft(SpecterOpenAiConfiguration configuration) {
			provider = configuration.provider();
			baseUrl = configuration.baseUrl();
			apiKey = configuration.apiKey();
			modelName = configuration.modelName();
			returnThinking = configuration.returnThinking();
			reasoningEffort = configuration.reasoningEffort();
		}

		private SpecterOpenAiConfiguration toConfiguration() {
			return SpecterOpenAiConfiguration.of(provider, baseUrl, apiKey, modelName,
				returnThinking, reasoningEffort);
		}

		@Override
		public String toString() {
			return toConfiguration().displayName();
		}
	}
}
