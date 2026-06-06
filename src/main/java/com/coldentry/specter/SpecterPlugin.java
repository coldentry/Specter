/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.coldentry.specter;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import java.awt.Component;

/**
 * Primary UI entry point for the Specter extension.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Specter",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Cold Entry reverse engineering assistant for Ghidra.",
	description = "Provides the initial Specter dockable UI and wiring point for future reverse engineering agent workflows."
)
//@formatter:on
public class SpecterPlugin extends ProgramPlugin {

	private SpecterTerminalProvider provider;
	private final SpecterModelConfigurationManager configurationManager;
	private final SpecterSubAgentConfigurationManager subAgentConfigurationManager;
	private final SpecterDisplayPreferences displayPreferences;
	private final SpecterCodeBrowserTools codeBrowserTools;
	private final SpecterSqlQueryService sqlQueryService;
	private final SpecterDslService dslService;
	private final SpecterChatService chatService;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public SpecterPlugin(PluginTool tool) {
		super(tool);
		configurationManager = new SpecterModelConfigurationManager();
		subAgentConfigurationManager = new SpecterSubAgentConfigurationManager();
		displayPreferences = new SpecterDisplayPreferences();
		codeBrowserTools = new SpecterCodeBrowserTools(this, subAgentConfigurationManager);
		sqlQueryService = new SpecterSqlQueryService(this::getCurrentProgram,
			new SpecterLlmPromptInvoker(configurationManager, codeBrowserTools));
		dslService = new SpecterDslService(sqlQueryService);
		codeBrowserTools.setDslService(dslService);
		codeBrowserTools.setSubAgentExecutor(new SpecterSubAgentExecutor(configurationManager,
			subAgentConfigurationManager, codeBrowserTools.coreToolHost())::invoke);
		chatService = SpecterChatServices.create(configurationManager, codeBrowserTools);

		String pluginName = getName();
		provider = new SpecterTerminalProvider(this, pluginName, chatService,
			configurationManager, subAgentConfigurationManager, displayPreferences, dslService);

		String topicName = "specter";
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();

		// Acquire services if necessary
	}

	Component dialogParent() {
		return provider == null ? null : provider.getComponent();
	}
}
