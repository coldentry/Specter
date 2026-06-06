package com.coldentry.specter;

import javax.swing.JComponent;

import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import resources.Icons;

class SpecterTerminalProvider extends ComponentProvider {

	private final SpecterTerminalPanel panel;
	private final DockingAction showTerminalAction;
	private final ToggleDockingAction showThinkingAction;

	SpecterTerminalProvider(Plugin plugin, String owner, SpecterChatService chatService,
			SpecterModelConfigurationManager configurationManager,
			SpecterSubAgentConfigurationManager subAgentConfigurationManager,
			SpecterDisplayPreferences displayPreferences,
			SpecterDslService dslService) {
		super(plugin.getTool(), "Specter", owner);

		panel = new SpecterTerminalPanel(chatService, configurationManager,
			subAgentConfigurationManager, displayPreferences, dslService);
		setTitle("Specter");
		setTabText("Specter");
		setIcon(Icons.INFO_ICON);
		setWindowGroup("Core");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setIntraGroupPosition(WindowPosition.BOTTOM);
		setWindowMenuGroup("Specter");
		setDefaultFocusComponent(panel.getInputComponent());

		showTerminalAction = new DockingAction("Show Specter", owner) {
			@Override
			public void actionPerformed(docking.ActionContext context) {
				setVisible(true);
				toFront();
				requestFocus();
			}
		};
		showTerminalAction.setToolBarData(new ToolBarData(Icons.INFO_ICON, null));
		showTerminalAction.setEnabled(true);
		showTerminalAction.markHelpUnnecessary();

		showThinkingAction = new ToggleDockingAction("Show Thinking", owner) {
			@Override
			public void actionPerformed(docking.ActionContext context) {
				panel.setThinkingVisible(!panel.isThinkingVisible());
			}
		};
		showThinkingAction.setDescription(
			"Show or hide assistant thinking when the current model returns it.");
		showThinkingAction.setMenuBarData(new MenuData(new String[] { "Show Thinking" }));
		showThinkingAction.setSelected(panel.isThinkingVisible());
		showThinkingAction.setEnabled(true);
		showThinkingAction.markHelpUnnecessary();
		panel.setThinkingVisibilityListener(showThinkingAction::setSelected);

		addToTool();
		addLocalAction(showTerminalAction);
		addLocalAction(showThinkingAction);
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
