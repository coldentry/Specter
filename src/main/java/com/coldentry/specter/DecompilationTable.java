package com.coldentry.specter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.DummyCancellableTaskMonitor;
import org.apache.calcite.DataContext;
import org.apache.calcite.config.CalciteConnectionConfig;
import org.apache.calcite.linq4j.AbstractEnumerable;
import org.apache.calcite.linq4j.Enumerable;
import org.apache.calcite.linq4j.Enumerator;
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

public class DecompilationTable implements ScannableTable {

    private Program program;

    public DecompilationTable(Program program) {
        this.program = program;
    }

    @Override
    public RelDataType getRowType(RelDataTypeFactory relDataTypeFactory) {
        return relDataTypeFactory.builder()
                .add("entry", SqlTypeName.BIGINT)
                .add("code", SqlTypeName.VARCHAR)
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

    private class DecompilationEnumerator implements Enumerator<Object[]> {
        private Program program;
        private DecompInterface decompInterface;
        private FunctionManager functionManager;
        private FunctionIterator functionIterator;
        private Function currentFunction;

        public DecompilationEnumerator(Program program) {
            this.program = program;
            this.decompInterface = new DecompInterface();
            this.decompInterface.openProgram(this.program);
            this.functionManager = program.getFunctionManager();
            reset();
        }

        @Override
        public Object[] current() {
            var decompiledFunction = decompInterface.decompileFunction(currentFunction, 60, new DummyCancellableTaskMonitor()).getDecompiledFunction();
            return new Object[] {
                    currentFunction.getEntryPoint().getOffset(),
                    decompiledFunction.getC()
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
            decompInterface.closeProgram();
        }
    }

    @Override
    public Enumerable<@Nullable Object[]> scan(DataContext dataContext) {
        return new AbstractEnumerable<Object[]>() {
            public Enumerator<Object[]> enumerator() {
                return new DecompilationEnumerator(program);
            }
        };
    }
}
