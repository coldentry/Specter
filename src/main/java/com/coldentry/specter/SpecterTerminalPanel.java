package com.coldentry.specter;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.CaretEvent;
import javax.swing.event.CaretListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import javax.swing.text.DefaultEditorKit;
import javax.swing.text.DocumentFilter;
import javax.swing.text.JTextComponent;

class SpecterTerminalPanel extends JPanel {

	private static final String DSL_PROMPT = "specter dsl> ";
	private static final String CHAT_PROMPT = "specter chat> ";
	private static final String ASSISTANT_PREFIX = "assistant> ";
	private static final String THINKING_PREFIX = "thinking> ";
	private static final String TOOL_PREFIX = "tool> ";
	private static final String TOOL_INPUT_PREFIX = "input> ";
	private static final String TOOL_OUTPUT_PREFIX = "output> ";
	private static final String DSL_TOOL_NAME = "RunSpecterDslQuery";
	private static final String NEW_COMMAND = "/new";
	private static final String HELP_COMMAND = "/help";
	private static final String MODEL_COMMAND = "/model";
	private static final String SUBAGENT_COMMAND = "/subagent";
	private static final String RESETPREFS_COMMAND = "/resetprefs";
	private static final String THINKING_COMMAND = "/thinking";
	private static final String DSL_COMMAND = "/dsl";
	private static final String THINKING_PLACEHOLDER = "thinking...";

	private final SpecterChatService chatService;
	private final SpecterModelConfigurationManager configurationManager;
	private final SpecterSubAgentConfigurationManager subAgentConfigurationManager;
	private final SpecterDisplayPreferences displayPreferences;
	private final SpecterDslService dslService;
	private final SpecterDatabaseEditPreferences databaseEditPreferences =
		new SpecterDatabaseEditPreferences();
	private final SpecterTerminalHistoryPreferences historyPreferences =
		new SpecterTerminalHistoryPreferences();
	private final JTextArea terminalArea = new JTextArea();
	private final JLabel usageLabel = new JLabel();
	private final ExecutorService chatExecutor =
		Executors.newSingleThreadExecutor(runnable -> {
			Thread thread = new Thread(runnable, "specter-chat");
			thread.setDaemon(true);
			return thread;
		});
	private final List<SpecterChatMessage> conversation = new ArrayList<>();
	private final List<SpecterTerminalEntry> transcript = new ArrayList<>();
	private final EnumMap<InputMode, InputModeState> modeStates = new EnumMap<>(InputMode.class);
	private final StringBuilder partialResponse = new StringBuilder();
	private final StringBuilder partialThinking = new StringBuilder();
	private int flushedThinkingLength;
	private int inputStartOffset;
	private boolean adjustingCaret;
	private boolean programmaticEdit;
	private boolean responseInFlight;
	private String usageStatus = "Usage: unavailable";
	private boolean thinkingVisible;
	private InputMode inputMode = InputMode.DSL;
	private long requestSequence;
	private long activeRequestId;
	private SpecterStreamingRequest activeStreamingRequest = SpecterStreamingRequest.NO_OP;
	private SpecterChatMessage inFlightUserMessage;
	private Consumer<Boolean> thinkingVisibilityListener = visible -> {
	};

	SpecterTerminalPanel(SpecterChatService chatService,
			SpecterModelConfigurationManager configurationManager,
			SpecterSubAgentConfigurationManager subAgentConfigurationManager,
			SpecterDisplayPreferences displayPreferences,
			SpecterDslService dslService) {
		super(new BorderLayout());
		this.chatService = chatService;
		this.configurationManager = configurationManager;
		this.subAgentConfigurationManager = subAgentConfigurationManager;
		this.displayPreferences = displayPreferences;
		this.dslService = dslService;
		for (InputMode mode : InputMode.values()) {
			modeStates.put(mode, new InputModeState(historyPreferences.loadHistory(mode.preferenceName())));
		}
		thinkingVisible = displayPreferences.showThinking();
		buildUi();
		appendBanner();
		renderTerminal("");
	}

	JComponent getInputComponent() {
		return terminalArea;
	}

	boolean isThinkingVisible() {
		return thinkingVisible;
	}

	void setThinkingVisible(boolean visible) {
		applyThinkingVisibility(visible, true, true);
	}

	private void setThinkingVisible(boolean visible, boolean renderAfterChange) {
		applyThinkingVisibility(visible, renderAfterChange, true);
	}

	private void applyThinkingVisibility(boolean visible, boolean renderAfterChange,
			boolean persistPreference) {
		if (thinkingVisible == visible) {
			return;
		}
		thinkingVisible = visible;
		if (persistPreference) {
			displayPreferences.setShowThinking(visible);
		}
		thinkingVisibilityListener.accept(visible);
		if (renderAfterChange) {
			renderTerminalPreservingInput();
		}
	}

	void setThinkingVisibilityListener(Consumer<Boolean> listener) {
		thinkingVisibilityListener = listener == null ? visible -> {
		} : listener;
	}

	private void buildUi() {
		setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

		terminalArea.setEditable(true);
		terminalArea.setLineWrap(true);
		terminalArea.setWrapStyleWord(true);
		terminalArea.setMargin(new Insets(10, 10, 10, 10));
		terminalArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
		terminalArea.setBackground(new Color(18, 18, 18));
		terminalArea.setForeground(new Color(230, 230, 230));
		terminalArea.setCaretColor(new Color(230, 230, 230));
		terminalArea.setBorder(BorderFactory.createEmptyBorder());
		terminalArea.setCaret(new BlockCaret());

		((AbstractDocument) terminalArea.getDocument()).setDocumentFilter(new TerminalDocumentFilter());
		terminalArea.addCaretListener(new TerminalCaretGuard());
		terminalArea.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				moveCaretToInput();
			}
		});

		configureKeyBindings();

		JScrollPane scrollPane = new JScrollPane(terminalArea);
		scrollPane.setBorder(BorderFactory.createLineBorder(new Color(45, 45, 45)));
		scrollPane.setPreferredSize(new Dimension(480, 260));

		usageLabel.setForeground(new Color(175, 175, 175));
		usageLabel.setBorder(BorderFactory.createEmptyBorder(6, 2, 0, 2));
		usageLabel.setText(usageStatus);

		add(scrollPane, BorderLayout.CENTER);
		add(usageLabel, BorderLayout.SOUTH);
	}

	private void configureKeyBindings() {
		terminalArea.getInputMap().put(KeyStroke.getKeyStroke("ENTER"), "specter-submit");
		terminalArea.getActionMap().put("specter-submit", new AbstractAction() {
			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				submitCurrentInput();
			}
		});

		terminalArea.getInputMap().put(KeyStroke.getKeyStroke("HOME"), "specter-home");
		terminalArea.getActionMap().put("specter-home", new AbstractAction() {
			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				moveCaretToInput();
			}
		});

		terminalArea.getInputMap().put(KeyStroke.getKeyStroke("UP"), "specter-history-previous");
		terminalArea.getActionMap().put("specter-history-previous", new AbstractAction() {
			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				navigateHistory(-1);
			}
		});

		terminalArea.getInputMap().put(KeyStroke.getKeyStroke("DOWN"), "specter-history-next");
		terminalArea.getActionMap().put("specter-history-next", new AbstractAction() {
			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				navigateHistory(1);
			}
		});

		terminalArea.getInputMap().put(KeyStroke.getKeyStroke("ESCAPE"), "specter-cancel-request");
		terminalArea.getActionMap().put("specter-cancel-request", new AbstractAction() {
			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				cancelCurrentRequest();
			}
		});

		terminalArea.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_M,
			InputEvent.CTRL_DOWN_MASK), "specter-toggle-input-mode");
		terminalArea.getActionMap().put("specter-toggle-input-mode", new AbstractAction() {
			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				toggleInputMode();
			}
		});

		wrapAction(DefaultEditorKit.backwardAction);
		wrapAction(DefaultEditorKit.deletePrevCharAction);
		wrapAction(DefaultEditorKit.selectionBackwardAction);
	}

	private void wrapAction(String actionKey) {
		Action original = terminalArea.getActionMap().get(actionKey);
		if (original == null) {
			return;
		}
		terminalArea.getActionMap().put(actionKey, new AbstractAction() {
			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				if (!canEditAtCaret()) {
					UIManager.getLookAndFeel().provideErrorFeedback(terminalArea);
					moveCaretToInput();
					return;
				}
				original.actionPerformed(e);
			}
		});
	}

	private boolean canEditAtCaret() {
		int selectionStart = terminalArea.getSelectionStart();
		int selectionEnd = terminalArea.getSelectionEnd();
		if (selectionStart != selectionEnd) {
			return selectionEnd > inputStartOffset;
		}
		return terminalArea.getCaretPosition() > inputStartOffset;
	}

	private void appendBanner() {
		SpecterOpenAiConfiguration configuration = configurationManager.currentConfiguration();
		appendOutput("Specter terminal ready.");
		appendOutput("Input mode: " + inputMode.displayName() +
			". Press Ctrl+M to switch between DSL and chat modes.");
		appendOutput("Slash commands: " + HELP_COMMAND + ", " + MODEL_COMMAND + ", " +
			SUBAGENT_COMMAND + ", " + RESETPREFS_COMMAND + ", " + NEW_COMMAND + ", " +
			THINKING_COMMAND + ", " + DSL_COMMAND + ".");
		appendOutput("Preferences node: " + SpecterPreferencesInfo.nodePath() + ".");
		appendOutput("Preferences storage: " +
			SpecterPreferencesInfo.storageLocationDescription() + ".");
		appendOutput("Use Up/Down to cycle through previous prompts and slash commands.");
		appendOutput("Press Esc to cancel an in-flight request.");
		if (configuration == null) {
			appendOutput("No model is configured.");
			appendOutput("If this is your first time using Specter, run " + MODEL_COMMAND +
				" to configure a model.");
		}
		else {
			appendOutput("Active model: " + configuration.displayName() + ".");
			appendOutput("Use " + MODEL_COMMAND +
				" to add model profiles, choose one, and change the active endpoint.");
		}
		appendOutput("");
	}

	private void submitCurrentInput() {
		if (responseInFlight) {
			UIManager.getLookAndFeel().provideErrorFeedback(terminalArea);
			return;
		}

		String currentInput = readCurrentInput();
		String message = currentInput.trim();
		if (message.isEmpty()) {
			UIManager.getLookAndFeel().provideErrorFeedback(terminalArea);
			return;
		}

		if (message.startsWith("/")) {
			recordInputHistory(message);
			transcript.add(SpecterTerminalEntry.user(message, currentPrompt()));
			handleSlashCommand(message);
			return;
		}
		if (inputMode == InputMode.DSL && shouldContinueDslInput(message)) {
			insertInputContinuationLine();
			return;
		}

		recordInputHistory(message);
		transcript.add(SpecterTerminalEntry.user(message, currentPrompt()));

		if (inputMode == InputMode.DSL) {
			handleDslScript(message);
			return;
		}

		if (!configurationManager.hasConfiguration()) {
			appendOutput("No model is configured. Run " + MODEL_COMMAND + " to configure one.");
			renderTerminal("");
			return;
		}

		SpecterChatMessage userMessage = SpecterChatMessage.user(message);
		conversation.add(userMessage);

		resetStreamingState();
		setResponseInFlight(true);
		renderTerminal("");

		List<SpecterChatMessage> conversationSnapshot = List.copyOf(conversation);
		long requestId = ++requestSequence;
		activeRequestId = requestId;
		inFlightUserMessage = userMessage;
		activeStreamingRequest = chatService.streamReply(conversationSnapshot,
			new TerminalStreamingListener(userMessage, requestId));
		chatExecutor.execute(activeStreamingRequest::run);
	}

	private void handleSlashCommand(String command) {
		resetStreamingState();
		switch (command) {
			case HELP_COMMAND -> showHelp();
			case MODEL_COMMAND -> showModelDialog();
			case SUBAGENT_COMMAND -> showSubAgentDialog();
			case RESETPREFS_COMMAND -> resetPreferences();
			case NEW_COMMAND -> resetConversation();
			case THINKING_COMMAND -> toggleThinkingFromCommand();
			case DSL_COMMAND -> showDslHelp();
			default -> {
				if (command.startsWith(THINKING_COMMAND + " ")) {
					handleThinkingCommand(command);
				}
				else if (command.startsWith(DSL_COMMAND + " ")) {
					handleDslCommand(command);
				}
				else {
					appendOutput("Unknown command: " + command);
					appendOutput("Run " + HELP_COMMAND + " to see available commands.");
					renderTerminal("");
				}
			}
		}
	}

	private void showHelp() {
		appendOutput("Available commands:");
		appendOutput("  " + HELP_COMMAND + " - shows the list of possible commands.");
		appendOutput("  " + MODEL_COMMAND + " - opens the model configuration dialog.");
		appendOutput("  " + SUBAGENT_COMMAND + " - opens the sub-agent configuration dialog.");
		appendOutput("  " + RESETPREFS_COMMAND +
			" - clears Specter preferences after confirmation.");
		appendOutput("  " + NEW_COMMAND + " - clears the current context.");
		appendOutput("  " + THINKING_COMMAND +
			" [show|hide|toggle] - controls whether assistant thinking is visible.");
		appendOutput("  " + DSL_COMMAND + " - shows Specter DSL help.");
		appendOutput("Input modes:");
		appendOutput("  specter dsl> - runs Specter DSL or plain SQL against the active program.");
		appendOutput("  specter chat> - sends prompts to the configured chat model.");
		appendOutput("  Press Ctrl+M to switch modes.");
		appendOutput("  Database-writing DSL statements prompt for approval before running.");
		appendOutput("  End DSL scripts with ; to submit; Enter adds another line until then.");
		appendOutput("Preferences node: " + SpecterPreferencesInfo.nodePath() + ".");
		appendOutput("Preferences storage: " +
			SpecterPreferencesInfo.storageLocationDescription() + ".");
		appendOutput("Input history: use Up/Down to recall previous inputs for the current mode.");
		appendOutput("Input history is saved across Ghidra sessions and cleared by " +
			RESETPREFS_COMMAND + ".");
		appendOutput("Press Esc while a response is streaming to cancel it.");
		renderTerminal("");
	}

	private void showDslHelp() {
		appendOutput(dslService.help());
		renderTerminal("");
	}

	private void handleDslCommand(String command) {
		String script = command.substring(DSL_COMMAND.length()).trim();
		if (!script.isEmpty()) {
			appendOutput("The " + DSL_COMMAND + " slash command no longer executes scripts. " +
				"Press Ctrl+M to switch to DSL mode, then enter the script without " +
				DSL_COMMAND + ".");
			renderTerminal("");
			return;
		}
		showDslHelp();
	}

	private void handleDslScript(String script) {
		resetStreamingState();
		setResponseInFlight(true);
		renderTerminal("");
		long requestId = ++requestSequence;
		activeRequestId = requestId;
		inFlightUserMessage = null;
		activeStreamingRequest = new DslStreamingRequest(script, requestId);
		chatExecutor.execute(activeStreamingRequest::run);
	}

	private void approveDslDatabaseEdit(String changeSummary) {
		String toolName = "RunSpecterDslQuery";
		if (databaseEditPreferences.alwaysAllow(toolName)) {
			return;
		}

		SpecterDatabaseEditApprovalDialog.Result result =
			SpecterDatabaseEditApprovalDialog.showDialog(this, toolName, changeSummary);
		if (!result.approved()) {
			throw new IllegalStateException(
				"User denied permission for DSL database write. No database changes were made.");
		}
		if (result.alwaysAllowFutureRuns()) {
			databaseEditPreferences.setAlwaysAllow(toolName, true);
		}
	}

	private void approveDslDatabaseEditOnEdt(String changeSummary) {
		if (SwingUtilities.isEventDispatchThread()) {
			approveDslDatabaseEdit(changeSummary);
			return;
		}
		try {
			SwingUtilities.invokeAndWait(() -> approveDslDatabaseEdit(changeSummary));
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted while waiting for DSL approval.", e);
		}
		catch (InvocationTargetException e) {
			Throwable cause = e.getCause();
			if (cause instanceof RuntimeException runtimeException) {
				throw runtimeException;
			}
			throw new IllegalStateException(cause == null ? e.getMessage() : cause.getMessage(),
				cause == null ? e : cause);
		}
	}

	private boolean shouldContinueDslInput(String input) {
		String trimmedInput = input == null ? "" : input.strip();
		if (inputMode != InputMode.DSL) {
			return false;
		}
		return !trimmedInput.endsWith(";");
	}

	private void insertInputContinuationLine() {
		runProgrammaticEdit(() -> terminalArea.insert("\n", terminalArea.getDocument().getLength()));
		moveCaretToEnd();
	}

	private void showModelDialog() {
		SpecterModelConfigurationDialog.Result result =
			SpecterModelConfigurationDialog.showDialog(this, configurationManager.snapshot());
		if (result != null) {
			try {
				configurationManager.updateConfigurations(result.configurations(),
					result.selectedIndex());
				resetUsageStatus();
				appendOutput("Active model changed to " +
					configurationManager.currentConfiguration().displayName() + ".");
			}
			catch (IllegalStateException e) {
				appendOutput("Unable to save model configuration: " + formatError(e));
			}
		}
		renderTerminal("");
	}

	private void showSubAgentDialog() {
		SpecterSubAgentConfigurationDialog.Result result =
			SpecterSubAgentConfigurationDialog.showDialog(this,
				subAgentConfigurationManager.snapshot());
		if (result != null) {
			try {
				subAgentConfigurationManager.updateDefinitions(result.definitions());
				int count = subAgentConfigurationManager.snapshot().definitions().size();
				appendOutput("Saved " + count + " sub-agent definition" +
					(count == 1 ? "." : "s."));
			}
			catch (IllegalStateException | IllegalArgumentException e) {
				appendOutput("Unable to save sub-agent configuration: " + formatError(e));
			}
		}
		renderTerminal("");
	}

	private void resetPreferences() {
		int choice = JOptionPane.showConfirmDialog(this,
			"Reset all Specter preferences?\n\n" +
				"This clears saved model profiles, sub-agents, and display settings.",
			"Reset Specter Preferences", JOptionPane.YES_NO_OPTION,
			JOptionPane.WARNING_MESSAGE);
		if (choice != JOptionPane.YES_OPTION) {
			appendOutput("Preference reset canceled.");
			renderTerminal("");
			return;
		}

		try {
			SpecterPreferencesInfo.clearAll();
			configurationManager.reloadFromPreferences();
			subAgentConfigurationManager.reloadFromPreferences();
			resetInputHistories();
			applyThinkingVisibility(displayPreferences.showThinking(), false, false);
			resetConversation();
			appendOutput(
				"Specter preferences were reset. Default sub-agents have been re-seeded.");
		}
		catch (IllegalStateException e) {
			appendOutput("Unable to reset preferences: " + formatError(e));
			renderTerminal("");
		}
	}

	private void resetConversation() {
		conversation.clear();
		transcript.clear();
		resetUsageStatus();
		appendBanner();
		resetStreamingState();
		renderTerminal("");
	}

	private void resetInputHistories() {
		for (InputMode mode : InputMode.values()) {
			modeStates.put(mode, new InputModeState(List.of()));
		}
	}

	private void recordInputHistory(String input) {
		InputModeState state = currentModeState();
		state.history.add(input);
		state.inputDraft = "";
		resetHistoryNavigation();
		historyPreferences.saveHistory(inputMode.preferenceName(), state.history);
	}

	private void resetHistoryNavigation() {
		InputModeState state = currentModeState();
		state.historyIndex = state.history.size();
		state.historyDraft = "";
	}

	private void runProgrammaticEdit(Runnable edit) {
		programmaticEdit = true;
		try {
			edit.run();
		}
		finally {
			programmaticEdit = false;
		}
	}

	private String readCurrentInput() {
		try {
			return terminalArea.getDocument().getText(
				inputStartOffset,
				terminalArea.getDocument().getLength() - inputStartOffset);
		}
		catch (BadLocationException e) {
			throw new IllegalStateException("Unable to read terminal input", e);
		}
	}

	private void appendOutput(String text) {
		transcript.add(SpecterTerminalEntry.output(text));
	}

	private void navigateHistory(int direction) {
		InputModeState state = currentModeState();
		if (responseInFlight || state.history.isEmpty()) {
			UIManager.getLookAndFeel().provideErrorFeedback(terminalArea);
			return;
		}

		int nextIndex = Math.max(0, Math.min(state.history.size(), state.historyIndex + direction));
		if (nextIndex == state.historyIndex) {
			UIManager.getLookAndFeel().provideErrorFeedback(terminalArea);
			return;
		}

		if (state.historyIndex == state.history.size()) {
			state.historyDraft = readCurrentInput();
		}

		state.historyIndex = nextIndex;
		replaceCurrentInput(state.historyIndex == state.history.size() ? state.historyDraft :
			state.history.get(state.historyIndex));
	}

	private void replaceCurrentInput(String text) {
		runProgrammaticEdit(() -> terminalArea.replaceRange(text, inputStartOffset,
			terminalArea.getDocument().getLength()));
		moveCaretToEnd();
	}

	private void toggleInputMode() {
		if (responseInFlight) {
			UIManager.getLookAndFeel().provideErrorFeedback(terminalArea);
			return;
		}
		currentModeState().inputDraft = readCurrentInput();
		inputMode = inputMode == InputMode.DSL ? InputMode.CHAT : InputMode.DSL;
		resetHistoryNavigation();
		InputModeState nextState = currentModeState();
		appendOutput("Input mode: " + inputMode.displayName() + ".");
		renderTerminal(nextState.inputDraft);
	}

	void dispose() {
		activeStreamingRequest.cancel();
		chatExecutor.shutdownNow();
	}

	private void setResponseInFlight(boolean inFlight) {
		responseInFlight = inFlight;
		terminalArea.setEditable(!inFlight);
	}

	private void finishResponse(SpecterAssistantReply response) {
		clearActiveRequest();
		updateUsageStatus(response.tokenUsage());
		if (response.hasContent()) {
			conversation.add(SpecterChatMessage.assistant(response.text(), response.thinking()));
			String unflushedThinking = unflushedThinking(response.thinking());
			if (!response.text().isEmpty() || !unflushedThinking.isEmpty()) {
				transcript.add(SpecterTerminalEntry.assistant(response.text(), unflushedThinking));
			}
		}
		resetStreamingState();
		setResponseInFlight(false);
		renderTerminal("");
	}

	private void failResponse(SpecterChatMessage userMessage, Throwable error) {
		conversation.remove(userMessage);
		clearActiveRequest();
		appendOutput("Request failed: " + formatError(error));
		resetStreamingState();
		setResponseInFlight(false);
		renderTerminal("");
	}

	private void cancelCurrentRequest() {
		if (!responseInFlight) {
			UIManager.getLookAndFeel().provideErrorFeedback(terminalArea);
			return;
		}

		activeStreamingRequest.cancel();
		if (inFlightUserMessage != null) {
			conversation.remove(inFlightUserMessage);
		}
		clearActiveRequest();
		appendOutput("user canceled request");
		resetStreamingState();
		setResponseInFlight(false);
		renderTerminal("");
	}

	private void appendPartialThinking(String partialThinking) {
		if (partialThinking == null || partialThinking.isEmpty()) {
			return;
		}
		this.partialThinking.append(partialThinking);
		renderTerminal("");
	}

	private void appendPartialResponse(String partialResponse) {
		if (partialResponse == null || partialResponse.isEmpty()) {
			return;
		}
		this.partialResponse.append(partialResponse);
		renderTerminal("");
	}

	private void appendToolCall(String toolName, String arguments) {
		if (toolName == null || toolName.isBlank()) {
			return;
		}
		flushPartialAssistantContent();
		transcript.add(SpecterTerminalEntry.toolCall(toolName, normalizeToolArguments(arguments)));
		renderTerminal("");
	}

	private void appendToolResult(String toolName, String result) {
		if (!DSL_TOOL_NAME.equals(toolName)) {
			return;
		}
		transcript.add(SpecterTerminalEntry.toolResult(normalizeToolResult(result)));
		renderTerminal("");
	}

	private void finishDslRequest(String result, long requestId) {
		if (requestId != activeRequestId) {
			return;
		}
		clearActiveRequest();
		flushPartialAssistantContent();
		appendOutput(result);
		resetStreamingState();
		setResponseInFlight(false);
		renderTerminal("");
	}

	private void failDslRequest(Throwable error, long requestId) {
		if (requestId != activeRequestId) {
			return;
		}
		clearActiveRequest();
		flushPartialAssistantContent();
		appendOutput("DSL error: " + formatError(error));
		resetStreamingState();
		setResponseInFlight(false);
		renderTerminal("");
	}

	private void resetStreamingState() {
		partialResponse.setLength(0);
		partialThinking.setLength(0);
		flushedThinkingLength = 0;
	}

	private void flushPartialAssistantContent() {
		if (partialResponse.isEmpty() && partialThinking.isEmpty()) {
			return;
		}
		transcript.add(SpecterTerminalEntry.assistant(
			partialResponse.toString(), partialThinking.toString()));
		flushedThinkingLength += partialThinking.length();
		partialResponse.setLength(0);
		partialThinking.setLength(0);
	}

	private String unflushedThinking(String thinking) {
		if (thinking == null || thinking.isEmpty()) {
			return "";
		}
		int start = Math.max(0, Math.min(flushedThinkingLength, thinking.length()));
		return thinking.substring(start);
	}

	private void clearActiveRequest() {
		activeRequestId = 0;
		activeStreamingRequest = SpecterStreamingRequest.NO_OP;
		inFlightUserMessage = null;
	}

	private String formatError(Throwable error) {
		if (error == null) {
			return "Unknown error";
		}

		String message = error.getMessage();
		return (message == null || message.isBlank()) ? error.getClass().getSimpleName() : message;
	}

	private void moveCaretToInput() {
		setCaretPosition(inputStartOffset);
	}

	private void moveCaretToEnd() {
		setCaretPosition(terminalArea.getDocument().getLength());
	}

	private void setCaretPosition(int offset) {
		int safeOffset = Math.max(0, Math.min(offset, terminalArea.getDocument().getLength()));
		adjustingCaret = true;
		try {
			terminalArea.setCaretPosition(safeOffset);
		}
		finally {
			adjustingCaret = false;
		}
	}

	private final class TerminalCaretGuard implements CaretListener {

		@Override
		public void caretUpdate(CaretEvent e) {
			if (adjustingCaret || programmaticEdit) {
				return;
			}

			if (terminalArea.getCaretPosition() < inputStartOffset &&
				terminalArea.getSelectionStart() == terminalArea.getSelectionEnd()) {
				moveCaretToInput();
			}
		}
	}

	private void toggleThinkingFromCommand() {
		boolean nextVisibility = !thinkingVisible;
		setThinkingVisible(nextVisibility, false);
		appendOutput("Assistant thinking is now " + (nextVisibility ? "shown." : "hidden."));
		renderTerminal("");
	}

	private void handleThinkingCommand(String command) {
		String mode = command.substring(THINKING_COMMAND.length()).trim();
		switch (mode) {
			case "show" -> {
				setThinkingVisible(true, false);
				appendOutput("Assistant thinking is now shown.");
			}
			case "hide" -> {
				setThinkingVisible(false, false);
				appendOutput("Assistant thinking is now hidden.");
			}
			case "toggle" -> {
				boolean nextVisibility = !thinkingVisible;
				setThinkingVisible(nextVisibility, false);
				appendOutput("Assistant thinking is now " +
					(nextVisibility ? "shown." : "hidden."));
			}
			default -> appendOutput("Usage: " + THINKING_COMMAND + " [show|hide|toggle]");
		}
		renderTerminal("");
	}

	private void renderTerminalPreservingInput() {
		renderTerminal(responseInFlight ? "" : readCurrentInput());
	}

	private void renderTerminal(String currentInput) {
		RenderedTerminal rendered = buildTerminal(currentInput);
		runProgrammaticEdit(() -> terminalArea.setText(rendered.text()));
		inputStartOffset = rendered.inputStartOffset();
		terminalArea.setEditable(!responseInFlight);
		usageLabel.setText(usageStatus);
		moveCaretToEnd();
	}

	private void updateUsageStatus(SpecterTokenUsage tokenUsage) {
		usageStatus = tokenUsage == null ? "Usage: unavailable" : tokenUsage.formatForDisplay();
	}

	private void resetUsageStatus() {
		usageStatus = "Usage: unavailable";
	}

	private RenderedTerminal buildTerminal(String currentInput) {
		StringBuilder builder = new StringBuilder();
		for (SpecterTerminalEntry entry : transcript) {
			appendEntry(builder, entry);
		}
		appendInFlightResponse(builder);
		if (!responseInFlight) {
			builder.append(currentPrompt());
			int inputOffset = builder.length();
			builder.append(currentInput);
			return new RenderedTerminal(builder.toString(), inputOffset);
		}
		return new RenderedTerminal(builder.toString(), builder.length());
	}

	private void appendEntry(StringBuilder builder, SpecterTerminalEntry entry) {
		switch (entry.kind()) {
			case OUTPUT -> builder.append(entry.text()).append("\n");
			case USER -> builder.append(entry.prompt()).append(entry.text()).append("\n");
			case ASSISTANT -> appendAssistantContent(builder, entry.text(), entry.thinking(), true);
			case TOOL_CALL -> appendToolCallEntry(builder, entry.text(), entry.toolArguments());
			case TOOL_RESULT -> appendToolResultEntry(builder, entry.text());
		}
	}

	private void appendInFlightResponse(StringBuilder builder) {
		if (!responseInFlight) {
			return;
		}
		appendAssistantContent(builder, partialResponse.toString(), partialThinking.toString(), false);
	}

	private void appendAssistantContent(StringBuilder builder, String response, String thinking,
			boolean appendTrailingNewline) {
		boolean wroteSection = false;
		if (thinking != null && !thinking.isEmpty()) {
			builder.append(renderThinking(thinking));
			wroteSection = true;
		}
		if (response != null && !response.isEmpty()) {
			if (wroteSection) {
				builder.append("\n");
			}
			builder.append(ASSISTANT_PREFIX).append(response);
			wroteSection = true;
		}
		if (wroteSection && appendTrailingNewline) {
			builder.append("\n");
		}
	}

	private String renderThinking(String thinking) {
		return thinkingVisible ? THINKING_PREFIX + thinking : THINKING_PLACEHOLDER;
	}

	private void appendToolCallEntry(StringBuilder builder, String toolName, String arguments) {
		builder.append(TOOL_PREFIX).append(toolName).append("\n");
		builder.append(TOOL_INPUT_PREFIX).append(arguments).append("\n");
	}

	private void appendToolResultEntry(StringBuilder builder, String result) {
		builder.append(TOOL_OUTPUT_PREFIX).append("\n");
		builder.append(result).append("\n");
	}

	private String normalizeToolArguments(String arguments) {
		if (arguments == null || arguments.isBlank()) {
			return "{}";
		}
		return arguments.strip();
	}

	private String normalizeToolResult(String result) {
		if (result == null || result.isBlank()) {
			return "(empty result)";
		}
		return result.strip();
	}

	private InputModeState currentModeState() {
		return modeStates.get(inputMode);
	}

	private String currentPrompt() {
		return inputMode == InputMode.DSL ? DSL_PROMPT : CHAT_PROMPT;
	}

	private enum InputMode {
		DSL("DSL", "dsl"),
		CHAT("chat", "chat");

		private final String displayName;
		private final String preferenceName;

		InputMode(String displayName, String preferenceName) {
			this.displayName = displayName;
			this.preferenceName = preferenceName;
		}

		String displayName() {
			return displayName;
		}

		String preferenceName() {
			return preferenceName;
		}
	}

	private static final class InputModeState {
		private final List<String> history = new ArrayList<>();
		private int historyIndex;
		private String historyDraft = "";
		private String inputDraft = "";

		private InputModeState(List<String> history) {
			this.history.addAll(history);
			historyIndex = this.history.size();
		}
	}

	private record RenderedTerminal(String text, int inputStartOffset) {
	}

	private final class TerminalDocumentFilter extends DocumentFilter {

		@Override
		public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
				throws BadLocationException {
			if (programmaticEdit) {
				super.insertString(fb, offset, string, attr);
				return;
			}
			super.insertString(fb, Math.max(offset, inputStartOffset), string, attr);
		}

		@Override
		public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
			if (programmaticEdit) {
				super.remove(fb, offset, length);
				return;
			}
			int safeOffset = Math.max(offset, inputStartOffset);
			int safeLength = length - (safeOffset - offset);
			if (safeLength <= 0) {
				UIManager.getLookAndFeel().provideErrorFeedback(terminalArea);
				return;
			}
			super.remove(fb, safeOffset, safeLength);
		}

		@Override
		public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
				throws BadLocationException {
			if (programmaticEdit) {
				super.replace(fb, offset, length, text, attrs);
				return;
			}
			int safeOffset = Math.max(offset, inputStartOffset);
			int safeLength = Math.max(0, length - (safeOffset - offset));
			super.replace(fb, safeOffset, safeLength, text, attrs);
		}
	}

	private final class TerminalStreamingListener implements SpecterStreamingResponseListener {

		private final SpecterChatMessage userMessage;
		private final long requestId;

		private TerminalStreamingListener(SpecterChatMessage userMessage, long requestId) {
			this.userMessage = userMessage;
			this.requestId = requestId;
		}

		@Override
		public void onPartialResponse(String partialResponse) {
			SwingUtilities.invokeLater(() -> {
				if (!ownsTerminal()) {
					return;
				}
				appendPartialResponse(partialResponse);
			});
		}

		@Override
		public void onPartialThinking(String partialThinking) {
			SwingUtilities.invokeLater(() -> {
				if (!ownsTerminal()) {
					return;
				}
				appendPartialThinking(partialThinking);
			});
		}

		@Override
		public void onToolCall(String toolName, String arguments) {
			SwingUtilities.invokeLater(() -> {
				if (!ownsTerminal()) {
					return;
				}
				appendToolCall(toolName, arguments);
			});
		}

		@Override
		public void onToolResult(String toolName, String result) {
			SwingUtilities.invokeLater(() -> {
				if (!ownsTerminal()) {
					return;
				}
				appendToolResult(toolName, result);
			});
		}

		@Override
		public void onComplete(SpecterAssistantReply completeResponse) {
			SwingUtilities.invokeLater(() -> {
				if (!ownsTerminal()) {
					return;
				}
				finishResponse(completeResponse);
			});
		}

		@Override
		public void onError(Throwable error) {
			SwingUtilities.invokeLater(() -> {
				if (!ownsTerminal()) {
					return;
				}
				failResponse(userMessage, error);
			});
		}

		private boolean ownsTerminal() {
			return requestId == activeRequestId;
		}
	}

	private final class DslStreamingRequest implements SpecterStreamingRequest {

		private final String script;
		private final long requestId;
		private final AtomicBoolean canceled = new AtomicBoolean();
		private volatile Thread workerThread;

		private DslStreamingRequest(String script, long requestId) {
			this.script = script;
			this.requestId = requestId;
		}

		@Override
		public void run() {
			if (canceled.get()) {
				return;
			}
			workerThread = Thread.currentThread();
			try {
				String result = dslService.execute(script,
					SpecterTerminalPanel.this::approveDslDatabaseEditOnEdt,
					new DslPromptStreamingListener(requestId));
				if (!canceled.get()) {
					SwingUtilities.invokeLater(() -> finishDslRequest(result, requestId));
				}
			}
			catch (Throwable error) {
				if (!canceled.get()) {
					SwingUtilities.invokeLater(() -> failDslRequest(error, requestId));
				}
			}
			finally {
				workerThread = null;
			}
		}

		@Override
		public void cancel() {
			canceled.set(true);
			Thread thread = workerThread;
			if (thread != null) {
				thread.interrupt();
			}
		}
	}

	private final class DslPromptStreamingListener implements SpecterStreamingResponseListener {

		private final long requestId;

		private DslPromptStreamingListener(long requestId) {
			this.requestId = requestId;
		}

		@Override
		public void onPartialResponse(String partialResponse) {
			// prompt() output is returned as the SQL cell value.
		}

		@Override
		public void onPartialThinking(String partialThinking) {
			SwingUtilities.invokeLater(() -> {
				if (!ownsTerminal()) {
					return;
				}
				appendPartialThinking(partialThinking);
			});
		}

		@Override
		public void onToolCall(String toolName, String arguments) {
			SwingUtilities.invokeLater(() -> {
				if (!ownsTerminal()) {
					return;
				}
				appendToolCall(toolName, arguments);
			});
		}

		@Override
		public void onToolResult(String toolName, String result) {
			SwingUtilities.invokeLater(() -> {
				if (!ownsTerminal()) {
					return;
				}
				appendToolResult(toolName, result);
			});
		}

		@Override
		public void onComplete(SpecterAssistantReply completeResponse) {
			// The SQL renderer owns final prompt() output.
		}

		@Override
		public void onError(Throwable error) {
			// The DSL request reports errors from the outer execution path.
		}

		private boolean ownsTerminal() {
			return requestId == activeRequestId;
		}
	}

	private static final class BlockCaret extends DefaultCaret {

		BlockCaret() {
			setBlinkRate(500);
		}

		@Override
		protected synchronized void damage(Rectangle r) {
			if (r == null) {
				return;
			}

			x = r.x;
			y = r.y;
			height = r.height;
			width = Math.max(r.width, 8);
			repaint();
		}

		@Override
		public void paint(Graphics g) {
			if (!isVisible()) {
				return;
			}

			JTextComponent component = getComponent();
			if (component == null) {
				return;
			}

			try {
				Rectangle r = component.modelToView2D(getDot()).getBounds();
				if (r == null) {
					return;
				}

				if ((x != r.x) || (y != r.y) || (height != r.height)) {
					damage(r);
				}

				g.setColor(component.getCaretColor());
				g.fillRect(r.x, r.y, Math.max(r.width, 8), r.height);
			}
			catch (BadLocationException e) {
				// Ignore invalid caret positions during document updates.
			}
		}
	}
}
