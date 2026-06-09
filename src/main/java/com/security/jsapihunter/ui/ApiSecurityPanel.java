package com.security.jsapihunter.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.security.jsapihunter.model.ApiEndpoint;
import com.security.jsapihunter.model.FuzzAttempt;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Part 8: the new "API Security" tab.
 * Sortable / filterable / searchable table with a right-click menu
 * (Send To Repeater / Intruder, Copy URL, Export CSV / JSON).
 */
public class ApiSecurityPanel extends JPanel {

    private final MontoyaApi api;
    private final ApiTableModel model = new ApiTableModel();
    private final JTable table;
    private final TableRowSorter<ApiTableModel> sorter;
    private final JTextField searchField = new JTextField(24);
    private final JCheckBox fuzzToggle = new JCheckBox("Enable Fuzz", true);

    // Right-hand detail: a per-attempt table over native Burp request/response viewers.
    private final FuzzAttemptTableModel attemptModel = new FuzzAttemptTableModel();
    private final JTable attemptTable = new JTable(attemptModel);
    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;

    public ApiSecurityPanel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;

        table = new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        // Default sort by the # column ascending so rows keep discovery order.
        table.getRowSorter().toggleSortOrder(0);

        requestViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        // Endpoint selected -> load its fuzz attempts into the attempts table.
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showAttempts();
        });
        // Attempt selected -> show its captured request/response packets.
        attemptTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showPackets();
        });

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(table), buildDetailPane());
        split.setResizeWeight(0.55);
        split.setDividerLocation(720);

        add(buildToolbar(), BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        installContextMenu();
    }

    /** Right side: attempts table on top, request/response viewers on the bottom. */
    private JPanel buildDetailPane() {
        JPanel panel = new JPanel(new BorderLayout());
        JLabel header = new JLabel("Fuzz attempts (click a row to view request / response)");
        header.setFont(new Font("Tahoma", Font.BOLD, 12));

        attemptTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        attemptTable.setFont(new Font("Consolas", Font.PLAIN, 12));
        attemptTable.getColumnModel().getColumn(0).setPreferredWidth(36);
        attemptTable.getColumnModel().getColumn(1).setPreferredWidth(220);

        JSplitPane packets = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestViewer.uiComponent(), responseViewer.uiComponent());
        packets.setResizeWeight(0.5);

        JSplitPane vertical = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(attemptTable), packets);
        vertical.setResizeWeight(0.35);
        vertical.setDividerLocation(220);

        panel.add(header, BorderLayout.NORTH);
        panel.add(vertical, BorderLayout.CENTER);
        return panel;
    }

    private void showAttempts() {
        ApiEndpoint ep = selectedEndpoint();
        attemptModel.setAttempts(ep == null ? List.of() : ep.getFuzzAttempts());
        clearPackets();
        if (attemptModel.getRowCount() > 0) {
            attemptTable.setRowSelectionInterval(0, 0);
        }
    }

    private void showPackets() {
        int row = attemptTable.getSelectedRow();
        if (row < 0) {
            clearPackets();
            return;
        }
        FuzzAttempt a = attemptModel.getAttempt(row);
        if (a == null || a.getExchange() == null) {
            clearPackets();
            return;
        }
        HttpRequestResponse rr = a.getExchange();
        requestViewer.setRequest(rr.request());
        responseViewer.setResponse(rr.response());
    }

    private void clearPackets() {
        try {
            requestViewer.setRequest(HttpRequest.httpRequest(""));
            responseViewer.setResponse(burp.api.montoya.http.message.responses.HttpResponse.httpResponse(""));
        } catch (Exception ignored) {
        }
    }

    private JPanel buildToolbar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bar.add(new JLabel("Search:"));
        bar.add(searchField);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });

        bar.add(fuzzToggle);

        JButton exportCsv = new JButton("Export CSV");
        exportCsv.addActionListener(e -> export(true));
        bar.add(exportCsv);

        JButton exportJson = new JButton("Export JSON");
        exportJson.addActionListener(e -> export(false));
        bar.add(exportJson);

        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> model.clear());
        bar.add(clear);

        return bar;
    }

    public boolean isFuzzEnabled() {
        return fuzzToggle.isSelected();
    }

    public JCheckBox fuzzToggle() {
        return fuzzToggle;
    }

    private void applyFilter() {
        String text = searchField.getText();
        if (text == null || text.isEmpty()) {
            sorter.setRowFilter(null);
            return;
        }
        try {
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text)));
        } catch (Exception ex) {
            sorter.setRowFilter(null);
        }
    }

    // ---- live updates from the scanner --------------------------------------

    public void addEndpoint(ApiEndpoint ep) {
        SwingUtilities.invokeLater(() -> model.addEndpoint(ep));
    }

    public void refreshEndpoint(ApiEndpoint ep) {
        SwingUtilities.invokeLater(() -> {
            model.updateEndpoint(ep);
            if (ep == selectedEndpoint()) {
                showAttempts();
            }
        });
    }

    // ---- right-click menu ----------------------------------------------------

    private void installContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem repeater = new JMenuItem("Send To Repeater");
        repeater.addActionListener(e -> sendSelected(true));
        menu.add(repeater);

        JMenuItem intruder = new JMenuItem("Send To Intruder");
        intruder.addActionListener(e -> sendSelected(false));
        menu.add(intruder);

        JMenuItem copy = new JMenuItem("Copy URL");
        copy.addActionListener(e -> copyUrl());
        menu.add(copy);

        menu.addSeparator();
        JMenuItem csv = new JMenuItem("Export CSV");
        csv.addActionListener(e -> export(true));
        menu.add(csv);
        JMenuItem json = new JMenuItem("Export JSON");
        json.addActionListener(e -> export(false));
        menu.add(json);

        table.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybeShow(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShow(e); }
            private void maybeShow(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0 && !table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                    menu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }

    private ApiEndpoint selectedEndpoint() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = table.convertRowIndexToModel(viewRow);
        return model.getEndpoint(modelRow);
    }

    private void sendSelected(boolean toRepeater) {
        ApiEndpoint ep = selectedEndpoint();
        if (ep == null) return;
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(ep.getUrl()).withMethod(ep.getMethod());
            if (toRepeater) {
                api.repeater().sendToRepeater(req);
            } else {
                api.intruder().sendToIntruder(req);
            }
        } catch (Exception ex) {
            api.logging().logToError("[JS API Hunter] send error: " + ex.getMessage());
        }
    }

    private void copyUrl() {
        ApiEndpoint ep = selectedEndpoint();
        if (ep == null) return;
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(ep.getUrl()), null);
    }

    private void export(boolean csv) {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File(csv ? "api_security.csv" : "api_security.json"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path path = chooser.getSelectedFile().toPath();
        List<ApiEndpoint> rows = model.snapshot();
        try {
            if (csv) {
                Exporter.toCsv(path, rows);
            } else {
                Exporter.toJson(path, rows);
            }
            JOptionPane.showMessageDialog(this, "Exported " + rows.size() + " rows to\n" + path);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
