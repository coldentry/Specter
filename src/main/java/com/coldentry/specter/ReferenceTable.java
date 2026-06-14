package com.coldentry.specter;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
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

public class ReferenceTable implements ScannableTable {

    private Program program;

    public ReferenceTable(Program program) {
        this.program = program;
    }

    @Override
    public RelDataType getRowType(RelDataTypeFactory relDataTypeFactory) {
        return relDataTypeFactory.builder()
                .add("from_address", SqlTypeName.BIGINT)
                .add("to_address", SqlTypeName.BIGINT)
                .add("type", SqlTypeName.VARCHAR)
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

    private class ReferenceEnumerator implements Enumerator<Object[]> {

        private Program program;
        private ReferenceManager referenceManager;
        private ReferenceIterator referenceIterator;
        private Reference currentReference;

        public ReferenceEnumerator(Program program) {
            this.program = program;
            this.referenceManager = program.getReferenceManager();
            reset();
        }

        @Override
        public Object[] current() {
            return new Object[] {
                    currentReference.getFromAddress().getOffset(),
                    currentReference.getToAddress().getOffset(),
                    String.valueOf(currentReference.getReferenceType()),
                    String.valueOf(currentReference.getSource())
            };
        }

        @Override
        public boolean moveNext() {
            currentReference = referenceIterator.next();
            return referenceIterator.hasNext();
        }

        @Override
        public void reset() {
            referenceIterator = referenceManager.getReferenceIterator(program.getMinAddress());
            currentReference = referenceIterator.next();
        }

        @Override
        public void close() {

        }
    }

    @Override
    public Enumerable<@Nullable Object[]> scan(DataContext dataContext) {
        return new AbstractEnumerable<Object[]>() {
            public Enumerator<Object[]> enumerator() {
                return new ReferenceEnumerator(program);
            }
        };
    }
}
