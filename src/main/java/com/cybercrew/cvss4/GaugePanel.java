package com.cybercrew.cvss4;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Arc2D;
import java.awt.geom.Path2D;
import java.awt.geom.Line2D;

import javax.swing.JComponent;

/**
 * Half-dial that fills from zero up to the score, coloured by severity, with the
 * score printed inside the dial.
 */
public final class GaugePanel extends JComponent
{
    /** Boundaries between the qualitative severity ratings, marked as notches. */
    private static final double[] NOTCHES = { 4.0, 7.0, 9.0 };

    private static final int PAD = 12;

    private final Palette palette;
    private double score;

    public GaugePanel(Palette palette)
    {
        this.palette = palette;
        setOpaque(false);
    }

    public void setScore(double score)
    {
        this.score = score;
        repaint();
    }

    @Override
    public Dimension getPreferredSize()
    {
        return new Dimension(236, 118);
    }

    @Override
    public Dimension getMaximumSize()
    {
        return getPreferredSize();
    }

    @Override
    public Dimension getMinimumSize()
    {
        return new Dimension(184, 104);
    }

    @Override
    protected void paintComponent(Graphics g)
    {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);

        Color severityColour = palette.forSeverity(Scorer.severity(score));

        double cx = getWidth() / 2.0;
        double radius = Math.min(Math.min(getWidth() / 2.0 - PAD, getHeight() - 20), 86);
        double cy = radius + PAD;
        double thickness = Math.max(10, radius * 0.19);

        g2.setStroke(new BasicStroke((float) thickness, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER));

        // Empty track
        g2.setColor(blend(palette.inkDim, palette.panel, 0.76));
        g2.draw(arc(cx, cy, radius, 0, 10));

        // Filled to the score
        if (score > 0)
        {
            g2.setColor(severityColour);
            g2.draw(arc(cx, cy, radius, 0, score));
        }

        // Notches at the severity boundaries, cut out of the ring
        g2.setColor(palette.panel);
        g2.setStroke(new BasicStroke(2f));
        for (double notch : NOTCHES)
        {
            double angle = Math.toRadians(180 - notch * 18);
            double inner = radius - thickness / 2;
            double outer = radius + thickness / 2;
            g2.draw(new Line2D.Double(
                    cx + inner * Math.cos(angle), cy - inner * Math.sin(angle),
                    cx + outer * Math.cos(angle), cy - outer * Math.sin(angle)));
        }

        // Pointer. It starts outside the score text so it never crosses the digits.
        double angle = Math.toRadians(180 - score * 18);
        double from = radius * 0.66;
        double to = radius + thickness / 2 + 5;

        g2.setColor(palette.ink);
        g2.fill(pointer(cx, cy, angle, from, to, 5.0));
        g2.setColor(palette.panel);
        g2.setStroke(new BasicStroke(1f));
        g2.draw(pointer(cx, cy, angle, from, to, 5.0));

        // The score itself, inside the dial
        Font big = getFont().deriveFont(Font.BOLD, (float) Math.max(24, radius * 0.5));
        g2.setFont(big);
        g2.setColor(palette.ink);
        String text = String.format("%.1f", score);
        FontMetrics metrics = g2.getFontMetrics();
        g2.drawString(text,
                (int) Math.round(cx - metrics.stringWidth(text) / 2.0),
                (int) Math.round(cy - radius * 0.22));

        g2.dispose();
    }

    /** A tapered needle from {@code from} to {@code to}, {@code halfWidth} wide at its base. */
    private static Path2D pointer(double cx, double cy, double angle,
            double from, double to, double halfWidth)
    {
        double ux = Math.cos(angle);
        double uy = -Math.sin(angle);
        double nx = -uy;
        double ny = ux;

        Path2D path = new Path2D.Double();
        path.moveTo(cx + from * ux + halfWidth * nx, cy + from * uy + halfWidth * ny);
        path.lineTo(cx + to * ux, cy + to * uy);
        path.lineTo(cx + from * ux - halfWidth * nx, cy + from * uy - halfWidth * ny);
        path.closePath();
        return path;
    }

    private static Arc2D arc(double cx, double cy, double radius, double from, double to)
    {
        return new Arc2D.Double(cx - radius, cy - radius, radius * 2, radius * 2,
                180 - from * 18, -(to - from) * 18, Arc2D.OPEN);
    }

    private static Color blend(Color colour, Color towards, double amount)
    {
        return new Color(
                (int) Math.round(colour.getRed() + (towards.getRed() - colour.getRed()) * amount),
                (int) Math.round(colour.getGreen() + (towards.getGreen() - colour.getGreen()) * amount),
                (int) Math.round(colour.getBlue() + (towards.getBlue() - colour.getBlue()) * amount));
    }
}
