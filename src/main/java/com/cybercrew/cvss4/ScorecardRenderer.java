package com.cybercrew.cvss4;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Arc2D;
import java.awt.geom.Path2D;
import java.awt.geom.Line2D;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Draws the score, severity and vector as a single image to drop into a report. */
public final class ScorecardRenderer
{
    private static final int WIDTH = 900;
    private static final int HEIGHT = 260;
    private static final double[][] BANDS = { { 0, 4 }, { 4, 7 }, { 7, 9 }, { 9, 10 } };

    private static final Color[] BAND_COLOURS = {
            new Color(0x3F, 0x91, 0x42), new Color(0xE0, 0x8A, 0x13),
            new Color(0xE0, 0x45, 0x2F), new Color(0x9C, 0x1A, 0x13) };

    public static BufferedImage render(Map<String, String> state, int scale)
    {
        double score = Scorer.score(state);
        Scorer.Severity severity = Scorer.severity(score);
        Color severityColour = switch (severity)
        {
            case NONE -> new Color(0x8A, 0x8A, 0x8A);
            case LOW -> BAND_COLOURS[0];
            case MEDIUM -> BAND_COLOURS[1];
            case HIGH -> BAND_COLOURS[2];
            case CRITICAL -> BAND_COLOURS[3];
        };

        BufferedImage image = new BufferedImage(WIDTH * scale, HEIGHT * scale, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        g.scale(scale, scale);

        g.setColor(Color.WHITE);
        g.fillRect(0, 0, WIDTH, HEIGHT);
        g.setColor(severityColour);
        g.fillRect(0, 0, WIDTH, 6);

        Color ink = new Color(0x24, 0x24, 0x24);
        Color inkDim = new Color(0x6A, 0x6A, 0x6A);

        // Dial: a neutral track filled up to the score
        double cx = 118;
        double cy = 152;
        double radius = 72;
        double thickness = 14;

        g.setStroke(new BasicStroke((float) thickness, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER));
        g.setColor(new Color(0xE2, 0xE4, 0xE6));
        g.draw(arc(cx, cy, radius, 0, 10));

        if (score > 0)
        {
            g.setColor(severityColour);
            g.draw(arc(cx, cy, radius, 0, score));
        }

        g.setColor(Color.WHITE);
        g.setStroke(new BasicStroke(2f));
        for (double notch : new double[] { 4, 7, 9 })
        {
            double a = Math.toRadians(180 - notch * 18);
            g.draw(new Line2D.Double(
                    cx + (radius - thickness / 2) * Math.cos(a), cy - (radius - thickness / 2) * Math.sin(a),
                    cx + (radius + thickness / 2) * Math.cos(a), cy - (radius + thickness / 2) * Math.sin(a)));
        }

        // Pointer, starting outside the score text so it never crosses the digits
        double angle = Math.toRadians(180 - score * 18);
        Path2D pointer = pointer(cx, cy, angle,
                radius * 0.66, radius + thickness / 2 + 5, 5.0);
        g.setColor(ink);
        g.fill(pointer);
        g.setColor(Color.WHITE);
        g.setStroke(new BasicStroke(1f));
        g.draw(pointer);

        Font sans = new Font(Font.SANS_SERIF, Font.PLAIN, 15);
        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 15);

        g.setFont(sans.deriveFont(Font.BOLD, 36f));
        g.setColor(ink);
        centre(g, String.format("%.1f", score), cx, (int) (cy - radius * 0.20));

        g.setFont(sans.deriveFont(Font.BOLD, 15f));
        g.setColor(severityColour);
        centre(g, severity.label(), cx, (int) cy + 26);

        int left = 250;
        g.setFont(sans.deriveFont(13f));
        g.setColor(inkDim);
        g.drawString("CVSS v4.0", left, 52);

        g.setFont(sans.deriveFont(Font.BOLD, 22f));
        g.setColor(ink);
        g.drawString(severity.label() + " severity, scoring " + String.format("%.1f", score), left, 80);

        g.setFont(mono);
        g.setColor(ink);
        List<String> lines = wrap(Metrics.toVector(state), g.getFontMetrics(), WIDTH - left - 30);
        int y = 118;
        for (String line : lines)
        {
            g.drawString(line, left, y);
            y += 22;
        }

        g.setFont(sans.deriveFont(12f));
        g.setColor(inkDim);
        g.drawString("MacroVector " + Scorer.macroVector(state)
                + "  \u00b7  nomenclature " + Scorer.nomenclature(state), left, y + 12);

        g.setFont(sans.deriveFont(11f));
        g.drawString(Cvss4Extension.CREDIT, left, HEIGHT - 18);

        g.dispose();
        return image;
    }

    private static Path2D pointer(double cx, double cy, double angle,
            double from, double to, double halfWidth)
    {
        double ux = Math.cos(angle);
        double uy = -Math.sin(angle);

        Path2D path = new Path2D.Double();
        path.moveTo(cx + from * ux + halfWidth * -uy, cy + from * uy + halfWidth * ux);
        path.lineTo(cx + to * ux, cy + to * uy);
        path.lineTo(cx + from * ux - halfWidth * -uy, cy + from * uy - halfWidth * ux);
        path.closePath();
        return path;
    }

    private static Arc2D arc(double cx, double cy, double radius, double from, double to)
    {
        return new Arc2D.Double(cx - radius, cy - radius, radius * 2, radius * 2,
                180 - from * 18, -(to - from) * 18, Arc2D.OPEN);
    }

    private static void centre(Graphics2D g, String text, double centreX, int baseline)
    {
        FontMetrics fm = g.getFontMetrics();
        g.drawString(text, (int) Math.round(centreX - fm.stringWidth(text) / 2.0), baseline);
    }

    /** Wraps the vector string on its slashes so it never runs off the card. */
    private static List<String> wrap(String vector, FontMetrics fm, int width)
    {
        List<String> lines = new ArrayList<>();
        StringBuilder current = new StringBuilder();

        String[] parts = vector.split("/");
        for (int i = 0; i < parts.length; i++)
        {
            String piece = (i == 0 ? "" : "/") + parts[i];
            if (current.length() > 0 && fm.stringWidth(current + piece) > width)
            {
                lines.add(current.toString());
                current = new StringBuilder(piece);
            }
            else
            {
                current.append(piece);
            }
        }
        lines.add(current.toString());
        return lines;
    }

    private ScorecardRenderer()
    {
    }
}
