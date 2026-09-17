package com.cybercrew.cvss4;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Definition of every CVSS v4.0 metric, in specification order. */
public final class Metrics
{
    /** One selectable value of a metric: {@code AV:N} shown to the analyst as "Network". */
    public record Option(String value, String label) { }

    /** One metric: its abbreviation, the name shown in the UI, and its allowed values. */
    public record Metric(String id, String name, List<Option> options)
    {
        public boolean allows(String value)
        {
            return options.stream().anyMatch(o -> o.value().equals(value));
        }
    }

    public static final String PREFIX = "CVSS:4.0";

    private static Option o(String value, String label)
    {
        return new Option(value, label);
    }

    private static Metric m(String id, String name, Option... options)
    {
        return new Metric(id, name, List.of(options));
    }

    private static final Option NOT_DEFINED = o("X", "Not Defined");

    private static Option[] cia()
    {
        return new Option[] { o("N", "None"), o("L", "Low"), o("H", "High") };
    }

    private static Option[] modified(Option... tail)
    {
        Option[] all = new Option[tail.length + 1];
        all[0] = NOT_DEFINED;
        System.arraycopy(tail, 0, all, 1, tail.length);
        return all;
    }

    // Base — exploitability
    public static final List<Metric> BASE_EXPLOITABILITY = List.of(
            m("AV", "Attack Vector", o("N", "Network"), o("A", "Adjacent"), o("L", "Local"), o("P", "Physical")),
            m("AC", "Attack Complexity", o("L", "Low"), o("H", "High")),
            m("AT", "Attack Requirements", o("N", "None"), o("P", "Present")),
            m("PR", "Privileges Required", o("N", "None"), o("L", "Low"), o("H", "High")),
            m("UI", "User Interaction", o("N", "None"), o("P", "Passive"), o("A", "Active")));

    // Base — impact on the vulnerable system
    public static final List<Metric> BASE_VULNERABLE = List.of(
            m("VC", "Confidentiality", cia()),
            m("VI", "Integrity", cia()),
            m("VA", "Availability", cia()));

    // Base — impact on subsequent systems
    public static final List<Metric> BASE_SUBSEQUENT = List.of(
            m("SC", "Confidentiality", cia()),
            m("SI", "Integrity", cia()),
            m("SA", "Availability", cia()));

    // Threat
    public static final List<Metric> THREAT = List.of(
            m("E", "Exploit Maturity", NOT_DEFINED, o("A", "Attacked"),
                    o("P", "Proof-of-Concept"), o("U", "Unreported")));

    // Environmental — security requirements
    private static Option[] requirement()
    {
        return new Option[] { NOT_DEFINED, o("L", "Low"), o("M", "Medium"), o("H", "High") };
    }

    public static final List<Metric> ENV_REQUIREMENTS = List.of(
            m("CR", "Confidentiality Req.", requirement()),
            m("IR", "Integrity Req.", requirement()),
            m("AR", "Availability Req.", requirement()));

    // Environmental — modified base
    public static final List<Metric> ENV_MODIFIED_EXPLOITABILITY = List.of(
            m("MAV", "Attack Vector", modified(o("N", "Network"), o("A", "Adjacent"), o("L", "Local"), o("P", "Physical"))),
            m("MAC", "Attack Complexity", modified(o("L", "Low"), o("H", "High"))),
            m("MAT", "Attack Requirements", modified(o("N", "None"), o("P", "Present"))),
            m("MPR", "Privileges Required", modified(o("N", "None"), o("L", "Low"), o("H", "High"))),
            m("MUI", "User Interaction", modified(o("N", "None"), o("P", "Passive"), o("A", "Active"))));

    public static final List<Metric> ENV_MODIFIED_VULNERABLE = List.of(
            m("MVC", "Confidentiality", modified(cia())),
            m("MVI", "Integrity", modified(cia())),
            m("MVA", "Availability", modified(cia())));

    public static final List<Metric> ENV_MODIFIED_SUBSEQUENT = List.of(
            m("MSC", "Confidentiality", modified(cia())),
            m("MSI", "Integrity", modified(o("N", "None"), o("L", "Low"), o("H", "High"), o("S", "Safety"))),
            m("MSA", "Availability", modified(o("N", "None"), o("L", "Low"), o("H", "High"), o("S", "Safety"))));

    // Supplemental — recorded in the vector, never scored
    public static final List<Metric> SUPPLEMENTAL = List.of(
            m("S", "Safety", NOT_DEFINED, o("N", "Negligible"), o("P", "Present")),
            m("AU", "Automatable", NOT_DEFINED, o("N", "No"), o("Y", "Yes")),
            m("R", "Recovery", NOT_DEFINED, o("A", "Automatic"), o("U", "User"), o("I", "Irrecoverable")),
            m("V", "Value Density", NOT_DEFINED, o("D", "Diffuse"), o("C", "Concentrated")),
            m("RE", "Response Effort", NOT_DEFINED, o("L", "Low"), o("M", "Moderate"), o("H", "High")),
            m("U", "Provider Urgency", NOT_DEFINED, o("Clear", "Clear"), o("Green", "Green"),
                    o("Amber", "Amber"), o("Red", "Red")));

    public static final List<Metric> ALL = concat(
            BASE_EXPLOITABILITY, BASE_VULNERABLE, BASE_SUBSEQUENT, THREAT, ENV_REQUIREMENTS,
            ENV_MODIFIED_EXPLOITABILITY, ENV_MODIFIED_VULNERABLE, ENV_MODIFIED_SUBSEQUENT, SUPPLEMENTAL);

    public static final List<String> BASE_IDS = ids(concat(BASE_EXPLOITABILITY, BASE_VULNERABLE, BASE_SUBSEQUENT));
    public static final List<String> THREAT_IDS = ids(THREAT);
    public static final List<String> ENV_IDS = ids(concat(ENV_REQUIREMENTS,
            ENV_MODIFIED_EXPLOITABILITY, ENV_MODIFIED_VULNERABLE, ENV_MODIFIED_SUBSEQUENT));

    /** Vector-string order, which is also the order metrics are written out. */
    public static final List<String> ORDER = ids(ALL);

    private static final Map<String, Metric> BY_ID = new LinkedHashMap<>();

    static
    {
        for (Metric metric : ALL)
        {
            BY_ID.put(metric.id(), metric);
        }
    }

    public static Metric byId(String id)
    {
        return BY_ID.get(id);
    }

    /** The state an unmodified form starts in: network-reachable, no impact, nothing else defined. */
    public static Map<String, String> defaults()
    {
        Map<String, String> state = new LinkedHashMap<>();
        for (String id : ORDER)
        {
            state.put(id, "X");
        }
        state.put("AV", "N");
        state.put("AC", "L");
        state.put("AT", "N");
        state.put("PR", "N");
        state.put("UI", "N");
        for (String id : List.of("VC", "VI", "VA", "SC", "SI", "SA"))
        {
            state.put(id, "N");
        }
        return state;
    }

    /** Renders the vector string: every base metric, plus anything else that is defined. */
    public static String toVector(Map<String, String> state)
    {
        StringBuilder out = new StringBuilder(PREFIX);
        for (String id : ORDER)
        {
            String value = state.getOrDefault(id, "X");
            if (BASE_IDS.contains(id) || !"X".equals(value))
            {
                out.append('/').append(id).append(':').append(value);
            }
        }
        return out.toString();
    }

    /**
     * Reads a vector string.
     *
     * @return the parsed state, or null if the string is not a complete, valid CVSS v4.0 vector
     */
    public static Map<String, String> parse(String vector)
    {
        if (vector == null)
        {
            return null;
        }

        String[] parts = vector.trim().split("/");
        if (parts.length == 0 || !PREFIX.equalsIgnoreCase(parts[0]))
        {
            return null;
        }

        Map<String, String> state = defaults();
        List<String> seen = new ArrayList<>();

        for (int i = 1; i < parts.length; i++)
        {
            String part = parts[i];
            if (part.isEmpty())
            {
                continue;
            }

            int colon = part.indexOf(':');
            if (colon < 1)
            {
                return null;
            }

            String id = part.substring(0, colon);
            String value = part.substring(colon + 1);
            Metric metric = BY_ID.get(id);

            if (metric == null || !metric.allows(value) || seen.contains(id))
            {
                return null;
            }

            state.put(id, value);
            seen.add(id);
        }

        return seen.containsAll(BASE_IDS) ? state : null;
    }

    @SafeVarargs
    private static List<Metric> concat(List<Metric>... groups)
    {
        List<Metric> all = new ArrayList<>();
        Arrays.stream(groups).forEach(all::addAll);
        return List.copyOf(all);
    }

    private static List<String> ids(List<Metric> metrics)
    {
        return metrics.stream().map(Metric::id).toList();
    }

    private Metrics()
    {
    }
}
