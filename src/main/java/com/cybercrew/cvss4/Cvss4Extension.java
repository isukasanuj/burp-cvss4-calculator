package com.cybercrew.cvss4;

import javax.swing.SwingUtilities;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.Theme;

/** Registers the CVSS 4.0 calculator as a Burp suite tab. */
public class Cvss4Extension implements BurpExtension
{
    public static final String NAME = "CVSS 4.0 Calculator";
    public static final String CREDIT = "Isuka Sanuj  \u00b7  CyberCrew inc";

    private static final String LAST_VECTOR = "cvss4.lastVector";

    private volatile CalculatorPanel panel;

    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName(NAME);

        Preferences preferences = api.persistence().preferences();

        api.extension().registerUnloadingHandler(() -> {
            // No background threads or listeners of our own to stop; drop the UI reference
            // so the panel and its state can be collected once Burp removes the tab.
            panel = null;
            api.logging().logToOutput(NAME + " unloaded.");
        });

        SwingUtilities.invokeLater(() -> {
            Palette palette = new Palette(api.userInterface().currentTheme() == Theme.DARK);

            CalculatorPanel calculator = new CalculatorPanel(
                    palette,
                    vector -> preferences.setString(LAST_VECTOR, vector),
                    () -> api.userInterface().swingUtils().suiteFrame(),
                    throwable -> api.logging().logToError(throwable));

            String saved = preferences.getString(LAST_VECTOR);
            if (saved != null && !saved.isBlank())
            {
                calculator.loadVector(saved);
            }

            panel = calculator;

            api.userInterface().applyThemeToComponent(calculator);
            api.userInterface().registerSuiteTab(NAME, calculator);

            api.logging().logToOutput(NAME + " loaded. Scoring follows the FIRST CVSS v4.0 specification.");
        });
    }
}
