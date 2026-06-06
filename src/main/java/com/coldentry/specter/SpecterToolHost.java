package com.coldentry.specter;

import java.util.List;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.agent.tool.ToolSpecification;
import ghidra.program.model.listing.Program;

interface SpecterToolHost {

	Program currentProgram();

	List<ToolSpecification> toolSpecifications();

	String execute(ToolExecutionRequest request);
}
