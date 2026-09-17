package com.cybercrew.cvss4;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.RenderingHints;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.ButtonGroup;
import javax.swing.JPanel;
import javax.swing.JToggleButton;

/** The row of mutually exclusive buttons that sets one metric, as in the Burp CVSS tab. */
public final class SegmentedControl extends JPanel
{
    private final Metrics.Metric metric;
    private final List<Segment> segments = new ArrayList<>();
    private final Palette palette;

    public SegmentedControl(Metrics.Metric metric, Palette palette, Consumer<String> onChange)
    {
        this.metric = metric;
        this.palette = palette;

        setLayout(new GridLayout(1, metric.options().size(), 0, 0));
        setOpaque(false);

        ButtonGroup group = new ButtonGroup();
        ActionListener listener = event -> onChange.accept(((Segment) event.getSource()).value);

        for (int i = 0; i < metric.options().size(); i++)
        {
            Metrics.Option option = metric.options().get(i);
            Segment segment = new Segment(option, i == 0);
            segment.addActionListener(listener);
            group.add(segment);
            segments.add(segment);
            add(segment);
        }
    }

    public String metricId()
    {
        return metric.id();
    }

    /** Moves the selection without firing the change listener. */
    public void showValue(String value)
    {
        for (Segment segment : segments)
        {
            if (segment.value.equals(value) != segment.isSelected())
            {
                segment.setSelectedQuietly(segment.value.equals(value));
            }
        }
    }

    private final class Segment extends JToggleButton
    {
        private final String value;
        private final boolean first;

        private Segment(Metrics.Option option, boolean first)
        {
            super(option.label());
            this.value = option.value();
            this.first = first;

            setToolTipText(metric.id() + ":" + option.value() + "  \u2014  " + metric.name());
            setFocusPainted(false);
            setRolloverEnabled(true);
            setContentAreaFilled(false);
            setBorderPainted(false);
            setOpaque(false);
            setMargin(new java.awt.Insets(0, 0, 0, 0));
            setFont(getFont().deriveFont(getFont().getSize2D() - 1f));
        }

        private void setSelectedQuietly(boolean selected)
        {
            ActionListener[] listeners = getActionListeners();
            for (ActionListener listener : listeners)
            {
                removeActionListener(listener);
            }
            setSelected(selected);
            for (ActionListener listener : listeners)
            {
                addActionListener(listener);
            }
        }

        @Override
        public Dimension getPreferredSize()
        {
            Dimension size = super.getPreferredSize();
            return new Dimension(Math.max(size.width + 14, 46), 24);
        }

        @Override
        protected void paintComponent(Graphics g)
        {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                    RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            int w = getWidth();
            int h = getHeight();
            boolean on = isSelected();
            boolean hover = getModel().isRollover();

            Color fill = on ? palette.selected : hover ? palette.buttonHover : palette.button;
            g2.setColor(fill);
            g2.fillRect(0, 0, w, h);

            g2.setColor(on ? palette.selected : palette.buttonEdge);
            g2.drawLine(0, 0, w - 1, 0);
            g2.drawLine(0, h - 1, w - 1, h - 1);
            if (first)
            {
                g2.drawLine(0, 0, 0, h - 1);
            }
            g2.drawLine(w - 1, 0, w - 1, h - 1);

            if (isFocusOwner())
            {
                g2.setColor(on ? palette.selectedInk : palette.selected);
                g2.drawRect(2, 2, w - 5, h - 5);
            }

            g2.setColor(on ? palette.selectedInk : palette.ink);
            g2.setFont(on ? getFont().deriveFont(java.awt.Font.BOLD) : getFont());

            String text = getText();
            java.awt.FontMetrics fm = g2.getFontMetrics();
            int available = w - 6;
            if (fm.stringWidth(text) > available)
            {
                while (text.length() > 1 && fm.stringWidth(text + "\u2026") > available)
                {
                    text = text.substring(0, text.length() - 1);
                }
                text = text + "\u2026";
            }
            int x = (w - fm.stringWidth(text)) / 2;
            int y = (h - fm.getHeight()) / 2 + fm.getAscent();
            g2.drawString(text, x, y);

            g2.dispose();
        }
    }
}
