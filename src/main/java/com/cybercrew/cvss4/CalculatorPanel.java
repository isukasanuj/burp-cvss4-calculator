package com.cybercrew.cvss4;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingWorker;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.SwingConstants;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;

/** The CVSS 4.0 tab: metric selection on the right, live risk analysis on the left. */
public final class CalculatorPanel extends JPanel
{
    private final Palette palette;
    private final Map<String, String> state = Metrics.defaults();
    private final List<SegmentedControl> controls = new ArrayList<>();
    private final Consumer<String> onVectorChanged;
    private final Supplier<Frame> dialogParent;
    private final Consumer<Throwable> errorSink;

    private final GaugePanel gauge;
    private final JLabel severityLabel = new JLabel("None", SwingConstants.CENTER);
    private final JLabel nomenclatureLabel = new JLabel("CVSS-B", SwingConstants.CENTER);
    private final JLabel macroLabel = new JLabel("000000");
    private final Map<String, JLabel[]> subScoreRows = new LinkedHashMap<>();
    private final JTextField vectorField = new JTextField();

    private boolean updating;

    public CalculatorPanel(Palette palette, Consumer<String> onVectorChanged,
            Supplier<Frame> dialogParent, Consumer<Throwable> errorSink)
    {
        this.palette = palette;
        this.onVectorChanged = onVectorChanged;
        this.dialogParent = dialogParent;
        this.errorSink = errorSink;
        this.gauge = new GaugePanel(palette);

        setLayout(new BorderLayout());
        setBackground(palette.panel);
        setBorder(BorderFactory.createEmptyBorder(14, 14, 10, 14));

        JPanel body = new JPanel(new BorderLayout(14, 0));
        body.setOpaque(false);
        body.add(buildRiskPanel(), BorderLayout.WEST);
        body.add(buildMetricsPanel(), BorderLayout.CENTER);

        add(body, BorderLayout.CENTER);
        add(buildActions(), BorderLayout.SOUTH);

        refresh();
    }

    // ------------------------------------------------------------------ risk

    private JComponent buildRiskPanel()
    {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setOpaque(false);
        panel.setBorder(titled("Risk Analysis"));
        panel.setPreferredSize(new Dimension(262, 0));

        gauge.setAlignmentX(CENTER_ALIGNMENT);
        panel.add(gauge);

        panel.add(Box.createVerticalStrut(10));

        severityLabel.setOpaque(true);
        severityLabel.setForeground(Color.WHITE);
        severityLabel.setFont(severityLabel.getFont().deriveFont(Font.BOLD, 14f));
        severityLabel.setBorder(BorderFactory.createEmptyBorder(7, 10, 7, 10));
        severityLabel.setAlignmentX(CENTER_ALIGNMENT);
        severityLabel.setMaximumSize(new Dimension(200, 32));
        panel.add(severityLabel);

        panel.add(Box.createVerticalStrut(8));

        nomenclatureLabel.setForeground(palette.ink);
        nomenclatureLabel.setFont(nomenclatureLabel.getFont().deriveFont(12f));
        nomenclatureLabel.setAlignmentX(CENTER_ALIGNMENT);
        nomenclatureLabel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 20));
        panel.add(nomenclatureLabel);

        panel.add(Box.createVerticalStrut(10));
        panel.add(separator());
        panel.add(Box.createVerticalStrut(8));

        JPanel scores = new JPanel(new GridBagLayout());
        scores.setOpaque(false);
        scores.setAlignmentX(CENTER_ALIGNMENT);
        addSubScoreRow(scores, 0, "B", "Base");
        addSubScoreRow(scores, 1, "BT", "Base + Threat");
        addSubScoreRow(scores, 2, "BE", "Base + Environmental");
        addSubScoreRow(scores, 3, "BTE", "All three");
        scores.setMaximumSize(new Dimension(Integer.MAX_VALUE, scores.getPreferredSize().height));
        panel.add(scores);

        panel.add(Box.createVerticalStrut(8));
        panel.add(separator());
        panel.add(Box.createVerticalStrut(6));

        JPanel macro = new JPanel(new BorderLayout());
        macro.setOpaque(false);
        JLabel macroCaption = new JLabel("MacroVector");
        macroCaption.setForeground(palette.inkDim);
        macroCaption.setFont(macroCaption.getFont().deriveFont(11f));
        macroLabel.setForeground(palette.ink);
        macroLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        macro.add(macroCaption, BorderLayout.WEST);
        macro.add(macroLabel, BorderLayout.EAST);
        macro.setMaximumSize(new Dimension(Integer.MAX_VALUE, 20));
        macro.setAlignmentX(CENTER_ALIGNMENT);
        panel.add(macro);

        panel.add(Box.createVerticalGlue());
        return panel;
    }

    private void addSubScoreRow(JPanel parent, int row, String key, String label)
    {
        JLabel name = new JLabel(label);
        name.setForeground(palette.inkDim);
        name.setFont(name.getFont().deriveFont(12f));

        JLabel value = new JLabel("\u2014");
        value.setForeground(palette.ink);
        value.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        GridBagConstraints left = new GridBagConstraints();
        left.gridx = 0;
        left.gridy = row;
        left.anchor = GridBagConstraints.WEST;
        left.weightx = 1;
        left.insets = new Insets(2, 0, 2, 12);

        GridBagConstraints right = new GridBagConstraints();
        right.gridx = 1;
        right.gridy = row;
        right.anchor = GridBagConstraints.EAST;
        right.insets = new Insets(2, 0, 2, 0);

        parent.add(name, left);
        parent.add(value, right);
        subScoreRows.put(key, new JLabel[] { name, value });
    }

    private JComponent separator()
    {
        JPanel line = new JPanel();
        line.setBackground(palette.rule);
        line.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        line.setPreferredSize(new Dimension(10, 1));
        line.setAlignmentX(CENTER_ALIGNMENT);
        return line;
    }

    // --------------------------------------------------------------- metrics

    private JComponent buildMetricsPanel()
    {
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.setOpaque(false);
        panel.setBorder(titled("CVSS Metrics"));

        JPanel top = new JPanel(new BorderLayout(8, 0));
        top.setBackground(palette.sunken);
        top.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(palette.rule),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)));

        vectorField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        vectorField.setBorder(null);
        vectorField.setOpaque(false);
        vectorField.setForeground(palette.ink);
        vectorField.setCaretColor(palette.ink);
        vectorField.setToolTipText("Edit or paste a CVSS v4.0 vector to load it");
        vectorField.getDocument().addDocumentListener(new DocumentListener()
        {
            @Override
            public void insertUpdate(DocumentEvent e)
            {
                vectorTyped();
            }

            @Override
            public void removeUpdate(DocumentEvent e)
            {
                vectorTyped();
            }

            @Override
            public void changedUpdate(DocumentEvent e)
            {
                vectorTyped();
            }
        });

        JButton reset = flatButton("Reset");
        reset.addActionListener(e -> {
            state.putAll(Metrics.defaults());
            refresh();
        });

        top.add(vectorField, BorderLayout.CENTER);
        top.add(reset, BorderLayout.EAST);
        panel.add(top, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Base", pane(baseTab()));
        tabs.addTab("Threat", pane(threatTab()));
        tabs.addTab("Environmental", pane(environmentalTab()));
        tabs.addTab("Supplemental", pane(supplementalTab()));
        panel.add(tabs, BorderLayout.CENTER);

        return panel;
    }

    /** A panel that shrinks to the viewport instead of being clipped when the tab is narrow. */
    private static final class WidthTracking extends JPanel implements javax.swing.Scrollable
    {
        private WidthTracking(java.awt.LayoutManager layout)
        {
            super(layout);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize()
        {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(java.awt.Rectangle visible, int orientation, int direction)
        {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(java.awt.Rectangle visible, int orientation, int direction)
        {
            return visible.height;
        }

        @Override
        public boolean getScrollableTracksViewportWidth()
        {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight()
        {
            return false;
        }
    }

    private JComponent pane(JComponent content)
    {
        JScrollPane scroll = new JScrollPane(content,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(palette.panel);
        scroll.setBackground(palette.panel);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }

    private JComponent baseTab()
    {
        return twoColumns(
                column(group("Exploitability", Metrics.BASE_EXPLOITABILITY)),
                column(group("Vulnerable system impact", Metrics.BASE_VULNERABLE),
                        group("Subsequent system impact", Metrics.BASE_SUBSEQUENT)));
    }

    private JComponent threatTab()
    {
        JComponent columns = oneColumn(column(group("Threat metrics", Metrics.THREAT)));
        return withNote(columns, "Exploit maturity describes what is known about exploitation in the "
                + "wild. Left undefined, the vulnerability scores as though it were already being attacked.");
    }

    private JComponent environmentalTab()
    {
        // One full-width column: five-value metrics such as MAV need the room.
        JComponent columns = oneColumn(
                column(group("Security requirements", Metrics.ENV_REQUIREMENTS),
                        group("Modified exploitability", Metrics.ENV_MODIFIED_EXPLOITABILITY),
                        group("Modified vulnerable system impact", Metrics.ENV_MODIFIED_VULNERABLE),
                        group("Modified subsequent system impact", Metrics.ENV_MODIFIED_SUBSEQUENT)));
        return withNote(columns, "Modified metrics override the matching base metric for this particular "
                + "deployment. Safety, on the subsequent-system impacts, marks a consequence that can harm people.");
    }

    private JComponent supplementalTab()
    {
        JComponent columns = oneColumn(
                column(group("Response and impact context", Metrics.SUPPLEMENTAL)));
        return withNote(columns, "Supplemental metrics travel with the vector but never change the score. "
                + "They give the receiving team context for prioritising the fix.");
    }

    private record Group(String title, List<Metrics.Metric> metrics) { }

    private Group group(String title, List<Metrics.Metric> metrics)
    {
        return new Group(title, metrics);
    }

    private JComponent column(Group... groups)
    {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setOpaque(false);

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;

        for (Group group : groups)
        {
            JLabel heading = new JLabel(group.title());
            heading.setForeground(palette.inkDim);
            heading.setFont(heading.getFont().deriveFont(11f));
            heading.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 0, 1, 0, palette.rule),
                    BorderFactory.createEmptyBorder(0, 0, 3, 0)));

            c.insets = new Insets(c.gridy == 0 ? 0 : 14, 0, 5, 0);
            panel.add(heading, c);
            c.gridy++;

            for (Metrics.Metric metric : group.metrics())
            {
                c.insets = new Insets(0, 0, 4, 0);
                panel.add(metricRow(metric), c);
                c.gridy++;
            }
        }

        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        JPanel filler = new JPanel();
        filler.setOpaque(false);
        panel.add(filler, c);

        return panel;
    }

    private JComponent metricRow(Metrics.Metric metric)
    {
        JPanel row = new JPanel(new BorderLayout(10, 0));
        row.setOpaque(false);

        JLabel label = new JLabel(metric.name(), SwingConstants.RIGHT);
        label.setForeground(palette.ink);
        label.setPreferredSize(new Dimension(150, 24));
        label.setMinimumSize(new Dimension(70, 24));
        label.setToolTipText(metric.id());

        SegmentedControl control = new SegmentedControl(metric, palette, value -> {
            state.put(metric.id(), value);
            refresh();
        });
        controls.add(control);

        row.add(label, BorderLayout.WEST);
        row.add(control, BorderLayout.CENTER);
        return row;
    }

    private JComponent oneColumn(JComponent content)
    {
        WidthTracking panel = new WidthTracking(new BorderLayout());
        panel.setBackground(palette.panel);
        panel.setBorder(BorderFactory.createEmptyBorder(12, 8, 8, 10));
        panel.add(content, BorderLayout.NORTH);
        return panel;
    }

    private JComponent twoColumns(JComponent left, JComponent right)
    {
        WidthTracking panel = new WidthTracking(new GridBagLayout());
        panel.setBackground(palette.panel);
        panel.setBorder(BorderFactory.createEmptyBorder(12, 8, 8, 10));

        GridBagConstraints c = new GridBagConstraints();
        c.gridy = 0;
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 0.5;
        c.weighty = 1;

        c.gridx = 0;
        c.insets = new Insets(0, 0, 0, 13);
        panel.add(left, c);

        c.gridx = 1;
        c.insets = new Insets(0, 13, 0, 0);
        panel.add(right, c);

        return panel;
    }

    private JComponent withNote(JComponent content, String text)
    {
        WidthTracking panel = new WidthTracking(new BorderLayout());
        panel.setBackground(palette.panel);
        panel.add(content, BorderLayout.CENTER);

        javax.swing.JTextArea note = new javax.swing.JTextArea(text);
        note.setEditable(false);
        note.setFocusable(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        note.setOpaque(false);
        note.setForeground(palette.inkDim);
        note.setFont(UIManager.getFont("Label.font").deriveFont(11f));
        note.setBorder(BorderFactory.createEmptyBorder(6, 16, 12, 16));
        note.setMaximumSize(new Dimension(560, Integer.MAX_VALUE));
        panel.add(note, BorderLayout.SOUTH);

        return panel;
    }

    // --------------------------------------------------------------- actions

    private JComponent buildActions()
    {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        row.setOpaque(false);

        JButton saveImage = new JButton("Save as image");
        saveImage.addActionListener(e -> saveImage());

        JButton copyVector = new JButton("Copy vector");
        copyVector.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(Metrics.toVector(state)), null);
        });

        row.add(saveImage);
        row.add(copyVector);

        JLabel credit = new JLabel(Cvss4Extension.CREDIT, SwingConstants.CENTER);
        credit.setForeground(palette.inkDim);
        credit.setFont(credit.getFont().deriveFont(11f));

        JPanel south = new JPanel(new BorderLayout());
        south.setOpaque(false);
        south.add(row, BorderLayout.CENTER);
        south.add(credit, BorderLayout.SOUTH);
        return south;
    }

    private void saveImage()
    {
        double score = Scorer.score(state);
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save CVSS scorecard");
        chooser.setFileFilter(new FileNameExtensionFilter("PNG image", "png"));
        chooser.setSelectedFile(new File("cvss-4.0-" + String.format("%.1f", score).replace('.', '-') + ".png"));

        if (chooser.showSaveDialog(parentWindow()) != JFileChooser.APPROVE_OPTION)
        {
            return;
        }

        File chosen = chooser.getSelectedFile();
        File target = chosen.getName().toLowerCase().endsWith(".png")
                ? chosen
                : new File(chosen.getParentFile(), chosen.getName() + ".png");

        // Snapshot the metrics so the worker is not reading state the analyst may still be editing.
        Map<String, String> snapshot = new LinkedHashMap<>(state);

        new SwingWorker<Void, Void>()
        {
            @Override
            protected Void doInBackground() throws Exception
            {
                ImageIO.write(ScorecardRenderer.render(snapshot, 2), "png", target);
                return null;
            }

            @Override
            protected void done()
            {
                try
                {
                    get();
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                }
                catch (ExecutionException e)
                {
                    report(e.getCause() == null ? e : e.getCause());
                }
            }
        }.execute();
    }

    private void report(Throwable cause)
    {
        if (errorSink != null)
        {
            errorSink.accept(cause);
        }

        JOptionPane.showMessageDialog(parentWindow(),
                "Could not write the image: " + cause.getMessage(),
                "Save as image", JOptionPane.WARNING_MESSAGE);
    }

    /** Dialogs hang off Burp's own frame so they land on the right monitor. */
    private java.awt.Component parentWindow()
    {
        Frame frame = dialogParent == null ? null : dialogParent.get();
        return frame != null ? frame : this;
    }

    // ---------------------------------------------------------------- update

    /** Loads a vector from outside the panel, for example the one saved last session. */
    public void loadVector(String vector)
    {
        Map<String, String> parsed = Metrics.parse(vector);
        if (parsed != null)
        {
            state.putAll(parsed);
            refresh();
        }
    }

    private void vectorTyped()
    {
        if (updating)
        {
            return;
        }

        Map<String, String> parsed = Metrics.parse(vectorField.getText());
        if (parsed == null)
        {
            vectorField.setForeground(palette.severityHigh);
            return;
        }

        vectorField.setForeground(palette.ink);
        state.putAll(parsed);
        refreshExceptVectorField();
    }

    private void refresh()
    {
        refreshExceptVectorField();

        updating = true;
        vectorField.setForeground(palette.ink);
        vectorField.setText(Metrics.toVector(state));
        updating = false;
    }

    private void refreshExceptVectorField()
    {
        for (SegmentedControl control : controls)
        {
            control.showValue(state.getOrDefault(control.metricId(), "X"));
        }

        double score = Scorer.score(state);
        Scorer.Severity severity = Scorer.severity(score);
        boolean hasThreat = Metrics.THREAT_IDS.stream().anyMatch(id -> !"X".equals(state.getOrDefault(id, "X")));
        boolean hasEnvironmental = Metrics.ENV_IDS.stream().anyMatch(id -> !"X".equals(state.getOrDefault(id, "X")));

        gauge.setScore(score);
        severityLabel.setText(severity.label());
        severityLabel.setBackground(palette.forSeverity(severity));
        nomenclatureLabel.setText("Nomenclature " + Scorer.nomenclature(state));
        macroLabel.setText(Scorer.macroVector(state));

        setSubScore("B", Scorer.score(state, false, false), true);
        setSubScore("BT", Scorer.score(state, true, false), hasThreat);
        setSubScore("BE", Scorer.score(state, false, true), hasEnvironmental);
        setSubScore("BTE", Scorer.score(state, true, true), hasThreat && hasEnvironmental);

        if (onVectorChanged != null)
        {
            onVectorChanged.accept(Metrics.toVector(state));
        }
    }

    private void setSubScore(String key, double score, boolean inPlay)
    {
        JLabel[] row = subScoreRows.get(key);
        row[1].setText(inPlay ? String.format("%.1f", score) : "\u2014");
        row[0].setForeground(inPlay ? palette.inkDim : fade(palette.inkDim));
        row[1].setForeground(inPlay ? palette.ink : fade(palette.ink));
    }

    private Color fade(Color colour)
    {
        return new Color(colour.getRed(), colour.getGreen(), colour.getBlue(), 90);
    }

    private TitledBorder titled(String title)
    {
        TitledBorder border = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(palette.rule), title);
        border.setTitleColor(palette.inkDim);
        return border;
    }

    private JButton flatButton(String text)
    {
        JButton button = new JButton(text);
        button.setFont(button.getFont().deriveFont(11f));
        button.setMargin(new Insets(2, 8, 2, 8));
        button.setFocusPainted(false);
        return button;
    }
}
