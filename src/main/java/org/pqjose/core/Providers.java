package org.pqjose.core;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

/** Provider registration and runtime capability detection (BC vs JDK built-ins). */
public final class Providers {

    public static final String BC = "BC";

    private Providers() {}

    public static void install() {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Providers that can produce a Signature for any of the given JCA algorithm names. */
    public static List<String> signatureProviders(String... jcaNames) {
        install();
        List<String> found = new ArrayList<>();
        for (Provider p : Security.getProviders()) {
            for (String name : jcaNames) {
                try {
                    Signature.getInstance(name, p.getName());
                    if (!found.contains(p.getName())) {
                        found.add(p.getName());
                    }
                    break;
                } catch (Exception ignored) {
                    // this provider does not offer this name; try the next candidate
                }
            }
        }
        return found;
    }

    /** First JCA name from the candidates that the given provider offers, or null. */
    public static String resolveJcaName(String providerName, String... jcaNames) {
        install();
        for (String name : jcaNames) {
            try {
                Signature.getInstance(name, providerName);
                return name;
            } catch (Exception ignored) {
                // fall through
            }
        }
        return null;
    }
}
