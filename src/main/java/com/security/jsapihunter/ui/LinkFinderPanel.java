package com.security.jsapihunter.ui;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Main tab, redesigned as master-detail:
 *   LEFT  - list of every passively scanned JS site (the .js URLs)
 *   RIGHT - when a site is clicked, two stacked boxes:
 *             Files  (top)    - filenames found in that JS
 *             Paths  (bottom) - normalized endpoint URLs found in that JS
 */
public class LinkFinderPanel extends JPanel {

    private static final Color ACCENT = new Color(255, 102, 52);

    /** Per-site discovery record. */
    private static class SiteRecord {
        final Set<String> files = new LinkedHashSet<>();
        final Set<String> paths = new LinkedHashSet<>();
    }

    private final Map<String, SiteRecord> sites = new LinkedHashMap<>();
    private final DefaultListModel<String> siteListModel = new DefaultListModel<>();
    private final JList<String> siteList = new JList<>(siteListModel);

    private final JTextArea filesArea = new JTextArea();
    private final JTextArea pathsArea = new JTextArea();

    public LinkFinderPanel() {
        super(new BorderLayout());

        siteList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        siteList.setFont(new Font("Consolas", Font.PLAIN, 12));
        siteList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelectedSite();
        });

        configure(filesArea);
        configure(pathsArea);

        JSplitPane right = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                wrap("Files:", filesArea, e -> filesArea.setText("")),
                wrap("Paths:", pathsArea, e -> pathsArea.setText("")));
        right.setResizeWeight(0.5);
        right.setDividerLocation(300);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildSitePanel(), right);
        split.setResizeWeight(0.32);
        split.setDividerLocation(360);

        add(split, BorderLayout.CENTER);
    }

    private JPanel buildSitePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(title("Scanned JS sites:"), BorderLayout.NORTH);
        panel.add(new JScrollPane(siteList), BorderLayout.CENTER);

        JPanel buttons = new JPanel();
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> clearAll());
        JButton export = new JButton("Export");
        export.addActionListener(e -> exportCurrent());
        buttons.add(clear);
        buttons.add(export);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel wrap(String labelText, JTextArea area, java.awt.event.ActionListener onClear) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(title(labelText), BorderLayout.NORTH);
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        JButton clear = new JButton("Clear");
        clear.addActionListener(onClear);
        panel.add(clear, BorderLayout.SOUTH);
        return panel;
    }

    private JLabel title(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Tahoma", Font.BOLD, 12));
        label.setForeground(ACCENT);
        return label;
    }

    private void configure(JTextArea area) {
        area.setFont(new Font("Consolas", Font.PLAIN, 12));
        area.setEditable(false);
        area.setLineWrap(true);
    }

    // ---- hooks used by the scanner (thread-safe via invokeLater) ------------

    /** Register a scanned JS site; adds it to the left list if new. */
    public void recordSite(String siteUrl) {
        if (siteUrl == null || siteUrl.isBlank()) return;
        SwingUtilities.invokeLater(() -> {
            if (!sites.containsKey(siteUrl)) {
                sites.put(siteUrl, new SiteRecord());
                siteListModel.addElement(siteUrl);
                if (siteList.getSelectedIndex() < 0) {
                    siteList.setSelectedIndex(siteListModel.size() - 1);
                }
            }
        });
    }

    /** Record a discovered path (normalized URL) under a site. */
    public void addPath(String siteUrl, String path) {
        if (siteUrl == null || path == null || path.isBlank()) return;
        SwingUtilities.invokeLater(() -> {
            SiteRecord rec = sites.computeIfAbsent(siteUrl, k -> {
                siteListModel.addElement(k);
                return new SiteRecord();
            });
            if (rec.paths.add(path) && siteUrl.equals(siteList.getSelectedValue())) {
                pathsArea.append((pathsArea.getText().isEmpty() ? "" : "\n") + path);
            }
        });
    }

    /** Record a discovered filename under a site. */
    public void addFile(String siteUrl, String file) {
        if (siteUrl == null || file == null || file.isBlank()) return;
        SwingUtilities.invokeLater(() -> {
            SiteRecord rec = sites.get(siteUrl);
            if (rec == null) return;
            if (rec.files.add(file) && siteUrl.equals(siteList.getSelectedValue())) {
                filesArea.append((filesArea.getText().isEmpty() ? "" : "\n") + file);
            }
        });
    }

    private void showSelectedSite() {
        String site = siteList.getSelectedValue();
        SiteRecord rec = site == null ? null : sites.get(site);
        if (rec == null) {
            filesArea.setText("");
            pathsArea.setText("");
            return;
        }
        filesArea.setText(String.join("\n", rec.files));
        pathsArea.setText(String.join("\n", rec.paths));
        filesArea.setCaretPosition(0);
        pathsArea.setCaretPosition(0);
    }

    private void clearAll() {
        sites.clear();
        siteListModel.clear();
        filesArea.setText("");
        pathsArea.setText("");
    }

    /** Export the currently selected site's files + paths to a text file. */
    private void exportCurrent() {
        String site = siteList.getSelectedValue();
        if (site == null) return;
        SiteRecord rec = sites.get(site);
        if (rec == null) return;
        JFileChooser chooser = new JFileChooser();
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try (BufferedWriter w = new BufferedWriter(new FileWriter(chooser.getSelectedFile()))) {
            w.write("# Site: " + site + "\n\n# Files:\n");
            for (String f : rec.files) w.write(f + "\n");
            w.write("\n# Paths:\n");
            for (String p : rec.paths) w.write(p + "\n");
        } catch (Exception ignored) {
        }
    }
}
