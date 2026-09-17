# CVSS 4.0 Calculator — Burp Suite extension

A CVSS v4.0 scoring tab for Burp Suite, built on the Montoya API.

Isuka Sanuj · CyberCrew inc

## Install

Burp → Extensions → Installed → Add → Extension type **Java** → select
`cvss4-calculator-1.0.0.jar`. A **CVSS 4.0 Calculator** tab appears in the suite tab strip.

Requires Burp Suite 2023.10 or later (Montoya API) and Java 17+.

## Build from source

    ./gradlew jar

The jar lands in `build/libs/`. Montoya is `compileOnly` — Burp provides it at runtime,
so it must not be bundled.

## What's in the tab

**Risk Analysis** — the dial fills from 0 to the score in the severity colour, with notches at
the 4.0 / 7.0 / 9.0 rating boundaries, a pointer at the current value, and the score printed
inside it. Below it: the severity, the nomenclature, and the CVSS-B / BT / BE / BTE sub-scores.
Sub-score rows stay greyed until the metrics behind them are actually set, so the
nomenclature always reflects what has been filled in. The MacroVector is shown at the
bottom, which is useful when a vendor disputes a score.

**CVSS Metrics** — the vector string at the top is editable: paste a vector and the form
loads it; invalid text turns red rather than discarding your work. Metrics are split
across four tabs because v4.0 has 32 of them:

| Tab | Metrics |
|---|---|
| Base | AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA |
| Threat | E |
| Environmental | CR, IR, AR, and the eleven modified base metrics |
| Supplemental | S, AU, R, V, RE, U |

**Save as image** writes a PNG scorecard — dial, score, wrapped vector, MacroVector — at
2× for reports. **Copy vector** puts the vector string on the clipboard.

The last vector is stored in Burp's project preferences and restored on load.

## Metric value order

Impact and requirement metrics run least to most severe — None, Low, High — so every row on
a tab reads the same direction. Modified subsequent impacts put Safety last, as the most
severe value. This is presentation only; vector strings are unaffected.

## Scoring

Implemented against the CVSS v4.0 MacroVector procedure, not an approximation: the
MacroVector lookup, highest-severity vectors and MacroVector depths in `Tables.java` are
the specification's own data.

The implementation was differential-tested against FIRST's reference calculator over all
104,976 base-metric combinations plus 60,000 randomised vectors covering threat,
environmental and modified metrics — zero divergence.

Behaviours worth knowing, all per specification:

- `E:X`, `CR:X`, `IR:X`, `AR:X` score as their worst case (`E:A`, `CR:H`, `IR:H`, `AR:H`).
- A modified metric overrides its base metric wherever both are set.
- `MSI:S` or `MSA:S` (Safety) puts the vector in equivalence set EQ4=0.
- Supplemental metrics are written into the vector and never affect the score.

## Source layout

| File | Role |
|---|---|
| `Cvss4Extension.java` | Montoya entry point, tab registration, preference storage |
| `CalculatorPanel.java` | The tab: risk panel, metric tabs, actions |
| `Metrics.java` | Metric definitions, vector build and parse |
| `Scorer.java` | MacroVector scoring |
| `Tables.java` | CVSS v4.0 specification data |
| `SegmentedControl.java` | The segmented toggle row |
| `GaugePanel.java` | Score dial |
| `ScorecardRenderer.java` | PNG export |
| `Palette.java` | Light and dark theming |

## BApp Store criteria

| Criterion | How this extension meets it |
|---|---|
| Unique function | CVSS v4.0 scoring inside Burp, with the full metric set and report export |
| Clear, descriptive name | CVSS 4.0 Calculator |
| Operates securely | Reads no HTTP traffic; the only input is the analyst's own vector string, which is validated before use |
| Includes all dependencies | None beyond the Montoya API, which Burp provides |
| Uses threads | The only slow operation, PNG export, runs in a `SwingWorker`; the metric state is snapshotted first. Failures go to the extension error stream |
| Unloads cleanly | `Extension.registerUnloadingHandler()`; no background threads or listeners are left running |
| Uses Burp networking | No network access at all |
| Supports offline working | Scoring data is compiled into the extension; nothing is fetched |
| Copes with large projects | Holds no references to HTTP messages or site map entries |
| Parents GUI elements | File chooser and message dialogs are parented to `SwingUtils.suiteFrame()` |
| Uses the Montoya API artifact | `compileOnly 'net.portswigger.burp.extensions:montoya-api'` via Gradle |
| Burp AI default provider | No AI functionality |

## Licence note

`Tables.java` carries the CVSS v4.0 lookup data published by FIRST
(BSD-2-Clause, © FIRST, Red Hat and contributors). Keep that header intact when
redistributing.
"# burp-cvss4-calculator" 
