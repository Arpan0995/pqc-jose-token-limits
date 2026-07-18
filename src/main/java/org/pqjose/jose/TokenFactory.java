package org.pqjose.jose;

import org.pqjose.core.Keys;
import org.pqjose.core.Providers;
import org.pqjose.core.SigAlg;
import org.pqjose.profiles.ClaimProfiles;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Signed kid-variant tokens for every available algorithm x claim profile (used by E2 and E5). */
public final class TokenFactory {

    public record TokenCase(SigAlg alg, String profile, String token) {}

    private TokenFactory() {}

    public static List<TokenCase> kidTokens() throws Exception {
        Providers.install();
        List<TokenCase> cases = new ArrayList<>();
        for (SigAlg alg : SigAlg.values()) {
            List<String> providers = alg.availableProviders();
            if (providers.isEmpty()) {
                continue;
            }
            String provider = providers.contains(Providers.BC) ? Providers.BC : providers.get(0);
            KeyPair kp = alg.generateKeyPair(provider);
            String kid = Keys.kid(kp.getPublic());
            for (Map.Entry<String, Map<String, Object>> profile : ClaimProfiles.all().entrySet()) {
                Map<String, Object> header = new LinkedHashMap<>();
                header.put("typ", profile.getKey().equals("oidc-id-token") ? "JWT" : "at+jwt");
                header.put("alg", alg.joseName);
                header.put("kid", kid);
                CompactJws.Token t = CompactJws.sign(alg, provider, kp.getPrivate(), header, profile.getValue());
                cases.add(new TokenCase(alg, profile.getKey(), t.compact()));
            }
        }
        return cases;
    }
}
