package com.security.jsfuzz.ui;

import com.security.jsfuzz.model.FuzzAttempt;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Lists the fuzz attempts of the currently selected endpoint, one row each.
 * Columns: #, Label, Status, Length, Hit.
 */
public class FuzzAttemptTableModel extends AbstractTableModel {

    public static final String[] COLUMNS = {"#", "Attempt", "Status", "Length", "Hit"};

    private final List<FuzzAttempt> rows = new ArrayList<>();

    public void setAttempts(List<FuzzAttempt> attempts) {
        rows.clear();
        if (attempts != null) {
            rows.addAll(attempts);
        }
        fireTableDataChanged();
    }

    public FuzzAttempt getAttempt(int row) {
        if (row < 0 || row >= rows.size()) return null;
        return rows.get(row);
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0: return Integer.class;
            case 2: return Integer.class;
            case 3: return Long.class;
            default: return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        FuzzAttempt a = rows.get(rowIndex);
        switch (columnIndex) {
            case 0: return rowIndex + 1;
            case 1: return a.getLabel();
            case 2: return a.getStatus();
            case 3: return a.getLength();
            case 4: return a.isInteresting() ? "!" : "";
            default: return "";
        }
    }
}
