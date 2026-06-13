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

public class FunctionTable implements ScannableTable {

    private FunctionManager functionManager;

    public FunctionTable(Program program) {
        functionManager = program.getFunctionManager();
    }

    @Override
    public RelDataType getRowType(RelDataTypeFactory relDataTypeFactory) {
        return relDataTypeFactory.builder()
                .add("entry", SqlTypeName.BIGINT)
                .add("name", SqlTypeName.VARCHAR)
                .add("namespace", SqlTypeName.VARCHAR)
                .add("signature", SqlTypeName.VARCHAR)
                .add("return_type", SqlTypeName.VARCHAR)
                .add("parameter_count", SqlTypeName.INTEGER)
                .add("body_min", SqlTypeName.BIGINT)
                .add("body_max", SqlTypeName.BIGINT)
                .add("body_size", SqlTypeName.BIGINT)
                .add("is_external", SqlTypeName.BOOLEAN)
                .add("is_thunk", SqlTypeName.BOOLEAN)
                .add("calling_convention", SqlTypeName.VARCHAR)
                .add("source", SqlTypeName.VARCHAR)
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
            return new Object[] {
                    currentFunction.getEntryPoint().getOffset(),
                    currentFunction.getName(),
                    currentFunction.getParentNamespace().getName(),
                    currentFunction.getSignature().getPrototypeString(),
                    currentFunction.getReturnType().getName(),
                    currentFunction.getParameterCount(),
                    currentFunction.getBody().getMinAddress().getOffset(),
                    currentFunction.getBody().getMaxAddress().getOffset(),
                    currentFunction.getBody().getNumAddresses(),
                    currentFunction.isExternal(),
                    currentFunction.isThunk(),
                    currentFunction.getCallingConventionName(),
                    currentFunction.getSymbol().getSource().getDisplayString()
            };
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
