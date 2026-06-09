package com.security.jsapihunter.ui;

import com.security.jsapihunter.model.ApiEndpoint;

import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Part 8: table model backing the API Security tab.
 * Columns: Method, URL, Status, Alive, Unauthorized, IDOR, Fuzz, Risk,
 *          Length, Title, Source JS, Time.
 */
public class ApiTableModel extends AbstractTableModel {

    public static final String[] COLUMNS = {
            "#", "Method", "URL", "Status", "Alive", "Unauthorized", "IDOR",
            "Fuzz", "Risk", "Length", "Title", "Source JS", "Time"
    };

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final List<ApiEndpoint> rows = new ArrayList<>();

    public synchronized void addEndpoint(ApiEndpoint ep) {
        rows.add(ep);
        int idx = rows.size() - 1;
        ep.setSeq(idx + 1);
        fireTableRowsInserted(idx, idx);
    }

    public synchronized void updateEndpoint(ApiEndpoint ep) {
        int idx = rows.indexOf(ep);
        if (idx >= 0) {
            fireTableRowsUpdated(idx, idx);
        }
    }

    public synchronized ApiEndpoint getEndpoint(int row) {
        if (row < 0 || row >= rows.size()) return null;
        return rows.get(row);
    }

    public synchronized List<ApiEndpoint> snapshot() {
        return new ArrayList<>(rows);
    }

    public synchronized void clear() {
        int n = rows.size();
        if (n > 0) {
            rows.clear();
            fireTableRowsDeleted(0, n - 1);
        }
    }

    @Override
    public synchronized int getRowCount() {
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
            case 0: // #
                return Integer.class;
            case 3: // Status
            case 9: // Length
                return Long.class;
            default:
                return String.class;
        }
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        ApiEndpoint ep = rows.get(rowIndex);
        switch (columnIndex) {
            case 0:  return ep.getSeq();
            case 1:  return ep.getMethod();
            case 2:  return ep.getUrl();
            case 3:  return (long) ep.getStatusCode();
            case 4:  return ep.getAlive();
            case 5:  return ep.getUnauthorized();
            case 6:  return ep.getIdor();
            case 7:  return ep.getFuzz();
            case 8:  return ep.getRisk().label();
            case 9:  return ep.getLength();
            case 10: return ep.getTitle();
            case 11: return ep.getSourceJs();
            case 12: return TIME_FMT.format(Instant.ofEpochMilli(ep.getDiscoveredAt()));
            default: return "";
        }
    }
}
