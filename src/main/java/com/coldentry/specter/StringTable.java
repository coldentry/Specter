package com.coldentry.specter;

import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.util.DefinedStringIterator;
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
import org.apache.velocity.runtime.directive.Define;
import org.checkerframework.checker.nullness.qual.Nullable;

public class StringTable implements ScannableTable {

    private Program program;

    public StringTable(Program program) {
        this.program = program;
    }

    @Override
    public RelDataType getRowType(RelDataTypeFactory relDataTypeFactory) {
        return relDataTypeFactory.builder()
                .add("address", SqlTypeName.BIGINT)
                .add("string_value", SqlTypeName.VARCHAR)
                .add("data_type", SqlTypeName.VARCHAR)
                .add("length", SqlTypeName.INTEGER)
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

    private class StringEnumerator implements Enumerator<Object[]> {

        private Program program;
        private DefinedStringIterator definedStringIterator;
        private Data currentString;

        public StringEnumerator(Program program) {
            this.program = program;
            reset();
        }

        @Override
        public Object[] current() {
            var sdi = StringDataInstance.getStringDataInstance(currentString);
            return new Object[] {
                    currentString.getAddress().getOffset(),
                    sdi.getStringValue(),
                    currentString.getDataType().getDisplayName(),
                    sdi.getStringLength()
            };
        }

        @Override
        public boolean moveNext() {
            currentString = definedStringIterator.next();
            return definedStringIterator.hasNext();
        }

        @Override
        public void reset() {
            definedStringIterator = DefinedStringIterator.forProgram(program);
            currentString = definedStringIterator.next();
        }

        @Override
        public void close() {

        }
    }

    @Override
    public Enumerable<@Nullable Object[]> scan(DataContext dataContext) {
        return new AbstractEnumerable<Object[]>() {
            public Enumerator<Object[]> enumerator() {
                return new StringEnumerator(program);
            }
        };
    }
}
