package com.security.jsapihunter.ui;

import com.security.jsapihunter.model.ApiEndpoint;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** Part 8: CSV / JSON export for the API Security results. */
public final class Exporter {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private Exporter() {
    }

    public static void toCsv(Path file, List<ApiEndpoint> rows) throws IOException {
        try (Writer w = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
            w.write(String.join(",", ApiTableModel.COLUMNS));
            w.write("\n");
            for (ApiEndpoint ep : rows) {
                String[] cells = {
                        String.valueOf(ep.getSeq()),
                        ep.getMethod(),
                        ep.getUrl(),
                        String.valueOf(ep.getStatusCode()),
                        ep.getAlive(),
                        ep.getUnauthorized(),
                        ep.getIdor(),
                        ep.getFuzz(),
                        ep.getRisk().label(),
                        String.valueOf(ep.getLength()),
                        ep.getTitle(),
                        ep.getSourceJs(),
                        TIME_FMT.format(Instant.ofEpochMilli(ep.getDiscoveredAt()))
                };
                StringBuilder line = new StringBuilder();
                for (int i = 0; i < cells.length; i++) {
                    if (i > 0) line.append(',');
                    line.append(csvCell(cells[i]));
                }
                w.write(line.toString());
                w.write("\n");
            }
        }
    }

    public static void toJson(Path file, List<ApiEndpoint> rows) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("[\n");
        for (int i = 0; i < rows.size(); i++) {
            ApiEndpoint ep = rows.get(i);
            sb.append("  {");
            sb.append("\"seq\":").append(ep.getSeq()).append(',');
            sb.append(jsonField("method", ep.getMethod())).append(',');
            sb.append(jsonField("url", ep.getUrl())).append(',');
            sb.append("\"status\":").append(ep.getStatusCode()).append(',');
            sb.append(jsonField("alive", ep.getAlive())).append(',');
            sb.append(jsonField("unauthorized", ep.getUnauthorized())).append(',');
            sb.append(jsonField("idor", ep.getIdor())).append(',');
            sb.append(jsonField("fuzz", ep.getFuzz())).append(',');
            sb.append(jsonField("risk", ep.getRisk().label())).append(',');
            sb.append("\"length\":").append(ep.getLength()).append(',');
            sb.append(jsonField("title", ep.getTitle())).append(',');
            sb.append(jsonField("sourceJs", ep.getSourceJs())).append(',');
            sb.append(jsonField("time", TIME_FMT.format(Instant.ofEpochMilli(ep.getDiscoveredAt()))));
            sb.append('}');
            if (i < rows.size() - 1) sb.append(',');
            sb.append('\n');
        }
        sb.append("]\n");
        Files.writeString(file, sb.toString(), StandardCharsets.UTF_8);
    }

    private static String csvCell(String v) {
        if (v == null) v = "";
        boolean needQuote = v.contains(",") || v.contains("\"") || v.contains("\n");
        v = v.replace("\"", "\"\"");
        return needQuote ? "\"" + v + "\"" : v;
    }

    private static String jsonField(String name, String value) {
        return "\"" + name + "\":\"" + escape(value) + "\"";
    }

    private static String escape(String v) {
        if (v == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:   sb.append(c);
            }
        }
        return sb.toString();
    }
}
