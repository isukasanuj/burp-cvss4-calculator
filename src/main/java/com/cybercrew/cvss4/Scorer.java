package com.cybercrew.cvss4;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * CVSS v4.0 scoring, following the MacroVector procedure in the specification:
 * find the MacroVector, take its score, then subtract the mean proportional
 * distance from the highest-severity vector inside it.
 */
public final class Scorer
{
    private static final Map<String, Map<String, Double>> LEVELS = Map.ofEntries(
            Map.entry("AV", Map.of("N", 0.0, "A", 0.1, "L", 0.2, "P", 0.3)),
            Map.entry("PR", Map.of("N", 0.0, "L", 0.1, "H", 0.2)),
            Map.entry("UI", Map.of("N", 0.0, "P", 0.1, "A", 0.2)),
            Map.entry("AC", Map.of("L", 0.0, "H", 0.1)),
            Map.entry("AT", Map.of("N", 0.0, "P", 0.1)),
            Map.entry("VC", Map.of("H", 0.0, "L", 0.1, "N", 0.2)),
            Map.entry("VI", Map.of("H", 0.0, "L", 0.1, "N", 0.2)),
            Map.entry("VA", Map.of("H", 0.0, "L", 0.1, "N", 0.2)),
            Map.entry("SC", Map.of("H", 0.1, "L", 0.2, "N", 0.3)),
            Map.entry("SI", Map.of("S", 0.0, "H", 0.1, "L", 0.2, "N", 0.3)),
            Map.entry("SA", Map.of("S", 0.0, "H", 0.1, "L", 0.2, "N", 0.3)),
            Map.entry("CR", Map.of("H", 0.0, "M", 0.1, "L", 0.2)),
            Map.entry("IR", Map.of("H", 0.0, "M", 0.1, "L", 0.2)),
            Map.entry("AR", Map.of("H", 0.0, "M", 0.1, "L", 0.2)));

    /** Metrics that score as their worst case while undefined. */
    private static final Map<String, String> WORST_WHILE_UNDEFINED =
            Map.of("E", "A", "CR", "H", "IR", "H", "AR", "H");

    private static final List<String> DISTANCE_METRICS = List.of(
            "AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR");

    private static final List<String> IMPACT_METRICS = List.of("VC", "VI", "VA", "SC", "SI", "SA");

    /** Severity bands from the specification's qualitative rating scale. */
    public enum Severity
    {
        NONE("None"), LOW("Low"), MEDIUM("Medium"), HIGH("High"), CRITICAL("Critical");

        private final String label;

        Severity(String label)
        {
            this.label = label;
        }

        public String label()
        {
            return label;
        }
    }

    public static Severity severity(double score)
    {
        if (score == 0.0)
        {
            return Severity.NONE;
        }
        if (score < 4.0)
        {
            return Severity.LOW;
        }
        if (score < 7.0)
        {
            return Severity.MEDIUM;
        }
        if (score < 9.0)
        {
            return Severity.HIGH;
        }
        return Severity.CRITICAL;
    }

    /** The value a metric scores as: a modified metric wins, then undefined-defaults. */
    private static String effective(Map<String, String> state, String id)
    {
        String modified = state.get("M" + id);
        if (modified != null && !"X".equals(modified))
        {
            return modified;
        }

        String value = state.get(id);
        if ((value == null || "X".equals(value)) && WORST_WHILE_UNDEFINED.containsKey(id))
        {
            return WORST_WHILE_UNDEFINED.get(id);
        }
        return value;
    }

    /** The six equivalence-set digits that identify this vector's MacroVector. */
    public static String macroVector(Map<String, String> state)
    {
        String av = effective(state, "AV");
        String pr = effective(state, "PR");
        String ui = effective(state, "UI");
        String ac = effective(state, "AC");
        String at = effective(state, "AT");
        String vc = effective(state, "VC");
        String vi = effective(state, "VI");
        String va = effective(state, "VA");
        String sc = effective(state, "SC");
        String si = effective(state, "SI");
        String sa = effective(state, "SA");
        String cr = effective(state, "CR");
        String ir = effective(state, "IR");
        String ar = effective(state, "AR");
        String e = effective(state, "E");

        int eq1;
        if ("N".equals(av) && "N".equals(pr) && "N".equals(ui))
        {
            eq1 = 0;
        }
        else if (("N".equals(av) || "N".equals(pr) || "N".equals(ui)) && !"P".equals(av))
        {
            eq1 = 1;
        }
        else
        {
            eq1 = 2;
        }

        int eq2 = "L".equals(ac) && "N".equals(at) ? 0 : 1;

        int eq3;
        if ("H".equals(vc) && "H".equals(vi))
        {
            eq3 = 0;
        }
        else if ("H".equals(vc) || "H".equals(vi) || "H".equals(va))
        {
            eq3 = 1;
        }
        else
        {
            eq3 = 2;
        }

        int eq4;
        if ("S".equals(state.get("MSI")) || "S".equals(state.get("MSA")))
        {
            eq4 = 0;
        }
        else if ("H".equals(sc) || "H".equals(si) || "H".equals(sa))
        {
            eq4 = 1;
        }
        else
        {
            eq4 = 2;
        }

        int eq5 = "A".equals(e) ? 0 : "P".equals(e) ? 1 : 2;

        boolean requirementMet = ("H".equals(cr) && "H".equals(vc))
                || ("H".equals(ir) && "H".equals(vi))
                || ("H".equals(ar) && "H".equals(va));
        int eq6 = requirementMet ? 0 : 1;

        return "" + eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
    }

    /** Reads one metric's value out of a highest-severity vector such as {@code AV:N/PR:N/UI:N/}. */
    private static String valueIn(String id, String vector)
    {
        String tail = vector.substring(vector.indexOf(id + ":") + id.length() + 1);
        int slash = tail.indexOf('/');
        return slash > 0 ? tail.substring(0, slash) : tail;
    }

    private static Double lookup(int eq1, int eq2, int eq3, int eq4, int eq5, int eq6)
    {
        return Tables.LOOKUP.get("" + eq1 + eq2 + eq3 + eq4 + eq5 + eq6);
    }

    /** Scores a full metric state, rounded to one decimal place. */
    public static double score(Map<String, String> state)
    {
        if (IMPACT_METRICS.stream().allMatch(id -> "N".equals(effective(state, id))))
        {
            return 0.0;
        }

        String macro = macroVector(state);
        Double base = Tables.LOOKUP.get(macro);
        if (base == null)
        {
            return 0.0;
        }

        double value = base;
        int eq1 = macro.charAt(0) - '0';
        int eq2 = macro.charAt(1) - '0';
        int eq3 = macro.charAt(2) - '0';
        int eq4 = macro.charAt(3) - '0';
        int eq5 = macro.charAt(4) - '0';
        int eq6 = macro.charAt(5) - '0';

        // The next lower MacroVector along each axis; absent means that axis is already at the bottom.
        Double lowerEq1 = lookup(eq1 + 1, eq2, eq3, eq4, eq5, eq6);
        Double lowerEq2 = lookup(eq1, eq2 + 1, eq3, eq4, eq5, eq6);
        Double lowerEq4 = lookup(eq1, eq2, eq3, eq4 + 1, eq5, eq6);
        Double lowerEq5 = lookup(eq1, eq2, eq3, eq4, eq5 + 1, eq6);
        Double lowerEq3Eq6;

        if (eq3 == 0 && eq6 == 0)
        {
            // Two ways down from here; the specification takes the higher-scoring one.
            Double left = lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
            Double right = lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
            double l = left == null ? Double.NEGATIVE_INFINITY : left;
            double r = right == null ? Double.NEGATIVE_INFINITY : right;
            lowerEq3Eq6 = l > r ? left : right;
        }
        else if (eq3 == 1 && eq6 == 0)
        {
            lowerEq3Eq6 = lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
        }
        else if (eq6 == 1 && (eq3 == 0 || eq3 == 1))
        {
            lowerEq3Eq6 = lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
        }
        else
        {
            lowerEq3Eq6 = lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1);
        }

        // Every combination of the highest-severity vectors for this MacroVector.
        List<String> candidates = new ArrayList<>();
        for (String a : Tables.EQ1_MAX[eq1])
        {
            for (String b : Tables.EQ2_MAX[eq2])
            {
                for (String c : Tables.EQ3_EQ6_MAX[eq3][eq6])
                {
                    for (String d : Tables.EQ4_MAX[eq4])
                    {
                        for (String f : Tables.EQ5_MAX[eq5])
                        {
                            candidates.add(a + b + c + d + f);
                        }
                    }
                }
            }
        }

        // The right one is the first that is at least as severe as this vector on every metric.
        Map<String, Double> distance = null;
        for (String candidate : candidates)
        {
            Map<String, Double> attempt = new java.util.HashMap<>();
            boolean viable = true;
            for (String id : DISTANCE_METRICS)
            {
                Map<String, Double> levels = LEVELS.get(id);
                double d = levels.get(effective(state, id)) - levels.get(valueIn(id, candidate));
                if (d < 0)
                {
                    viable = false;
                    break;
                }
                attempt.put(id, d);
            }
            if (viable)
            {
                distance = attempt;
                break;
            }
        }

        if (distance == null)
        {
            return round(value);
        }

        double severityEq1 = distance.get("AV") + distance.get("PR") + distance.get("UI");
        double severityEq2 = distance.get("AC") + distance.get("AT");
        double severityEq3Eq6 = distance.get("VC") + distance.get("VI") + distance.get("VA")
                + distance.get("CR") + distance.get("IR") + distance.get("AR");
        double severityEq4 = distance.get("SC") + distance.get("SI") + distance.get("SA");

        double depthEq1 = Tables.DEPTH_EQ1[eq1] * 0.1;
        double depthEq2 = Tables.DEPTH_EQ2[eq2] * 0.1;
        double depthEq3Eq6 = Tables.DEPTH_EQ3_EQ6[eq3][eq6] * 0.1;
        double depthEq4 = Tables.DEPTH_EQ4[eq4] * 0.1;

        int existingLower = 0;
        double total = 0.0;

        if (lowerEq1 != null)
        {
            existingLower++;
            total += (value - lowerEq1) * (severityEq1 / depthEq1);
        }
        if (lowerEq2 != null)
        {
            existingLower++;
            total += (value - lowerEq2) * (severityEq2 / depthEq2);
        }
        if (lowerEq3Eq6 != null)
        {
            existingLower++;
            total += (value - lowerEq3Eq6) * (severityEq3Eq6 / depthEq3Eq6);
        }
        if (lowerEq4 != null)
        {
            existingLower++;
            total += (value - lowerEq4) * (severityEq4 / depthEq4);
        }
        if (lowerEq5 != null)
        {
            // The proportion along EQ5 is always zero.
            existingLower++;
        }

        if (existingLower > 0)
        {
            value -= total / existingLower;
        }

        return round(Math.min(10.0, Math.max(0.0, value)));
    }

    /** Scores the vector with whole metric groups masked out, for the CVSS-B / BT / BE sub-scores. */
    public static double score(Map<String, String> state, boolean withThreat, boolean withEnvironmental)
    {
        Map<String, String> masked = new java.util.LinkedHashMap<>(state);
        if (!withThreat)
        {
            Metrics.THREAT_IDS.forEach(id -> masked.put(id, "X"));
        }
        if (!withEnvironmental)
        {
            Metrics.ENV_IDS.forEach(id -> masked.put(id, "X"));
        }
        return score(masked);
    }

    /** CVSS-B, CVSS-BT, CVSS-BE or CVSS-BTE, depending on which groups the analyst filled in. */
    public static String nomenclature(Map<String, String> state)
    {
        boolean threat = Metrics.THREAT_IDS.stream().anyMatch(id -> !"X".equals(state.getOrDefault(id, "X")));
        boolean environmental = Metrics.ENV_IDS.stream().anyMatch(id -> !"X".equals(state.getOrDefault(id, "X")));
        return "CVSS-B" + (threat ? "T" : "") + (environmental ? "E" : "");
    }

    private static double round(double value)
    {
        return Math.round(value * 10.0) / 10.0;
    }

    private Scorer()
    {
    }
}
