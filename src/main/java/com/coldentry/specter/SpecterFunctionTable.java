package com.coldentry.specter;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import org.apache.calcite.DataContext;
import org.apache.calcite.config.CalciteConnectionConfig;
import org.apache.calcite.linq4j.*;
import org.apache.calcite.rel.type.RelDataType;
import org.apache.calcite.rel.type.RelDataTypeFactory;
import org.apache.calcite.schema.ScannableTable;
import org.apache.calcite.schema.Schema;
import org.apache.calcite.schema.Statistic;
import org.apache.calcite.schema.Statistics;
import org.apache.calcite.sql.SqlCall;
import org.apache.calcite.sql.SqlNode;
import org.apache.calcite.sql.type.SqlTypeName;
import org.checkerframework.checker.nullness.qual.Nullable;

public class SpecterFunctionTable implements ScannableTable {

    private FunctionManager functionManager;

    public SpecterFunctionTable(Program program) {
        functionManager = program.getFunctionManager();
    }

    @Override
    public RelDataType getRowType(RelDataTypeFactory relDataTypeFactory) {
        return relDataTypeFactory.builder()
                .add("entry", SqlTypeName.BIGINT)
                .add("name", SqlTypeName.VARCHAR)
                .build();
    }

    @Override
    public Statistic getStatistic() {
        return Statistics.UNKNOWN;
    }

    @Override
    public Schema.TableType getJdbcTableType() {
        return Schema.TableType.TABLE;
    }

    @Override
    public boolean isRolledUp(String s) {
        return false;
    }

    @Override
    public boolean rolledUpColumnValidInsideAgg(String s, SqlCall sqlCall, @Nullable SqlNode sqlNode, @Nullable CalciteConnectionConfig calciteConnectionConfig) {
        return false;
    }

    private class FunctionEnumerator implements Enumerator<Object[]> {

        private FunctionManager functionManager;
        private FunctionIterator functionIterator;
        private Function currentFunction;

        public FunctionEnumerator(FunctionManager functionManager) {
            this.functionManager = functionManager;
            reset();
        }

        @Override
        public Object[] current() {
            return new Object[]{ currentFunction.getEntryPoint().getOffset(), currentFunction.getName() };
        }

        @Override
        public boolean moveNext() {
            currentFunction = functionIterator.next();
            return functionIterator.hasNext();
        }

        @Override
        public void reset() {
            functionIterator = functionManager.getFunctions(true);
            currentFunction = functionIterator.next();
        }

        @Override
        public void close() {

        }
    }

    @Override
    public Enumerable<@Nullable Object[]> scan(DataContext dataContext) {
        return new AbstractEnumerable<Object[]>() {
            public Enumerator<Object[]> enumerator() {
                return new FunctionEnumerator(functionManager);
            }
        };
    }
}
