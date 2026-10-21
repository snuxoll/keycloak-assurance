package com.snuxoll.keycloak.upstreammfa;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;

import org.keycloak.models.Constants;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.core.type.TypeReference;

/**
 * The upstream {@code amr} as it travels between components: a JSON array of strings in a user-session note.
 */
public final class UpstreamAmr {

    public static final String DEFAULT_NOTE = "upstream.amr";
    public static final String DEFAULT_CLAIM = "amr";

    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() {};

    private UpstreamAmr() {
    }

    public static String toNote(List<String> amr) {
        try {
            return JsonSerialization.writeValueAsString(amr);
        } catch (IOException e) {
            throw new IllegalStateException("Could not serialize amr", e);
        }
    }

    /**
     * Parses a note written by {@link #toNote}. Anything missing or malformed yields an empty list, so callers
     * fail safe: no upstream methods means no trust.
     */
    public static List<String> fromNote(String note) {
        if (note == null || note.isBlank()) {
            return List.of();
        }
        try {
            List<String> amr = JsonSerialization.readValue(note, STRING_LIST);
            return amr == null ? List.of() : amr.stream().filter(v -> v != null && !v.isBlank()).toList();
        } catch (IOException | RuntimeException e) {
            return List.of();
        }
    }

    /**
     * Normalizes a raw claim value: a JSON array of strings, or a single string. Anything else yields an empty list.
     */
    public static List<String> fromClaim(Object claim) {
        if (claim instanceof String value) {
            return value.isBlank() ? List.of() : List.of(value);
        }
        if (claim instanceof Collection<?> values) {
            List<String> amr = new ArrayList<>();
            for (Object value : values) {
                if (value instanceof String s && !s.isBlank()) {
                    amr.add(s);
                }
            }
            return amr;
        }
        return List.of();
    }

    /** Local values first, then upstream values not already present. */
    public static List<String> merge(List<String> local, List<String> upstream) {
        LinkedHashSet<String> merged = new LinkedHashSet<>(local);
        merged.addAll(upstream);
        return new ArrayList<>(merged);
    }

    /** Reads a config value, falling back to a default when it is unset or blank. */
    public static String configOrDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    /** Splits a multivalued-string config value as stored by the admin console. */
    public static List<String> splitMultivalued(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return List.of(value.split(Constants.CFG_DELIMITER)).stream()
                .map(String::trim)
                .filter(v -> !v.isEmpty())
                .toList();
    }
}
