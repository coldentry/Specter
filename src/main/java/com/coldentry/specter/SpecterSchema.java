package com.coldentry.specter;

import ghidra.program.model.listing.Program;
import org.apache.calcite.schema.Table;
import org.apache.calcite.schema.impl.AbstractSchema;

import java.util.Map;

public class SpecterSchema extends AbstractSchema {

    private Program program;

    public SpecterSchema(Program program) {
        this.program = program;
    }

    @Override
    public Map<String, Table> getTableMap() {
        return Map.of(
                "function", new SpecterFunctionTable(program)
        );
    }
}
