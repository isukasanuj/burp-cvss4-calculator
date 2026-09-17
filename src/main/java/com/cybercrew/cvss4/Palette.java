package com.cybercrew.cvss4;

import java.awt.Color;

import javax.swing.UIManager;

/** Colours for the calculator, following whichever theme Burp is running. */
public final class Palette
{
    public final boolean dark;

    public final Color panel;
    public final Color sunken;
    public final Color rule;
    public final Color ink;
    public final Color inkDim;
    public final Color button;
    public final Color buttonEdge;
    public final Color buttonHover;
    public final Color selected;
    public final Color selectedInk;
    public final Color accent;

    public final Color severityNone;
    public final Color severityLow;
    public final Color severityMedium;
    public final Color severityHigh;
    public final Color severityCritical;

    public Palette(boolean dark)
    {
        this.dark = dark;

        if (dark)
        {
            panel = new Color(0x31, 0x33, 0x35);
            sunken = new Color(0x29, 0x2B, 0x2D);
            rule = new Color(0x4B, 0x4E, 0x51);
            ink = new Color(0xDF, 0xE1, 0xE5);
            inkDim = new Color(0x9A, 0xA0, 0xA6);
            button = new Color(0x3A, 0x3D, 0x3F);
            buttonEdge = new Color(0x55, 0x58, 0x5B);
            buttonHover = new Color(0x43, 0x48, 0x4D);
            selected = new Color(0x3D, 0x84, 0xC6);
            selectedInk = new Color(0x0F, 0x11, 0x13);
            severityNone = new Color(0x8A, 0x8A, 0x8A);
            severityLow = new Color(0x5F, 0xB5, 0x62);
            severityMedium = new Color(0xF0, 0xA2, 0x38);
            severityHigh = new Color(0xEF, 0x6A, 0x55);
            severityCritical = new Color(0xD1, 0x49, 0x3C);
        }
        else
        {
            panel = new Color(0xFF, 0xFF, 0xFF);
            sunken = new Color(0xF7, 0xF7, 0xF7);
            rule = new Color(0xC6, 0xC6, 0xC6);
            ink = new Color(0x24, 0x24, 0x24);
            inkDim = new Color(0x6A, 0x6A, 0x6A);
            button = new Color(0xFB, 0xFB, 0xFB);
            buttonEdge = new Color(0xB4, 0xB4, 0xB4);
            buttonHover = new Color(0xEE, 0xF3, 0xF8);
            selected = new Color(0x1F, 0x6B, 0xB0);
            selectedInk = Color.WHITE;
            severityNone = new Color(0x8A, 0x8A, 0x8A);
            severityLow = new Color(0x3F, 0x91, 0x42);
            severityMedium = new Color(0xE0, 0x8A, 0x13);
            severityHigh = new Color(0xE0, 0x45, 0x2F);
            severityCritical = new Color(0x9C, 0x1A, 0x13);
        }

        accent = new Color(0xFF, 0x66, 0x33);
    }

    public Color forSeverity(Scorer.Severity severity)
    {
        return switch (severity)
        {
            case NONE -> severityNone;
            case LOW -> severityLow;
            case MEDIUM -> severityMedium;
            case HIGH -> severityHigh;
            case CRITICAL -> severityCritical;
        };
    }

    /** Guesses the theme from the look and feel, for when Burp has not told us. */
    public static boolean looksDark()
    {
        Color background = UIManager.getColor("Panel.background");
        if (background == null)
        {
            return false;
        }
        double luminance = (0.299 * background.getRed()
                + 0.587 * background.getGreen()
                + 0.114 * background.getBlue()) / 255.0;
        return luminance < 0.5;
    }
}
