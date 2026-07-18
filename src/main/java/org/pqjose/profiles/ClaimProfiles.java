package org.pqjose.profiles;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Three fixed, realistic claim sets. All values are static so every run and every
 * algorithm signs byte-identical payloads; only the header and signature vary.
 *
 * MINIMAL_ACCESS  – RFC 9068 JWT access token, lean deployment.
 * OIDC_ID_TOKEN   – typical OpenID Connect ID token with standard profile claims.
 * ENTERPRISE      – access token with directory group bloat (25 AD-style DNs, roles,
 *                   tenant metadata), modeled on real Azure AD / Okta deployments.
 */
public final class ClaimProfiles {

    public static final String ISS = "https://as.example.gov";
    public static final String SUB = "9f8c7e2a-4b1d-4c6e-9a3f-2d5b8e1c7a90";
    public static final long IAT = 1_784_246_400L;   // fixed epoch so payloads are stable
    public static final long EXP = IAT + 3600;

    private ClaimProfiles() {}

    public static Map<String, Map<String, Object>> all() {
        Map<String, Map<String, Object>> profiles = new LinkedHashMap<>();
        profiles.put("minimal-access", minimalAccess());
        profiles.put("oidc-id-token", oidcIdToken());
        profiles.put("enterprise-access", enterpriseAccess());
        return profiles;
    }

    public static Map<String, Object> minimalAccess() {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("iss", ISS);
        c.put("sub", SUB);
        c.put("aud", "https://api.example.gov");
        c.put("exp", EXP);
        c.put("iat", IAT);
        c.put("jti", "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f");
        c.put("client_id", "s6BhdRkqt3");
        c.put("scope", "openid profile email");
        return c;
    }

    public static Map<String, Object> oidcIdToken() {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("iss", ISS);
        c.put("sub", SUB);
        c.put("aud", "s6BhdRkqt3");
        c.put("exp", EXP);
        c.put("iat", IAT);
        c.put("auth_time", IAT - 5);
        c.put("nonce", "n-0S6_WzA2Mj");
        c.put("acr", "urn:mace:incommon:iap:silver");
        c.put("amr", List.of("pwd", "otp"));
        c.put("azp", "s6BhdRkqt3");
        c.put("name", "Jordan Example");
        c.put("given_name", "Jordan");
        c.put("family_name", "Example");
        c.put("preferred_username", "jordan.example");
        c.put("email", "jordan.example@example.gov");
        c.put("email_verified", true);
        c.put("picture", "https://idp.example.gov/photos/9f8c7e2a.jpg");
        return c;
    }

    public static Map<String, Object> enterpriseAccess() {
        Map<String, Object> c = minimalAccess();
        c.put("tid", "72f988bf-86f1-41af-91ab-2d7cd011db47");
        c.put("scp", "User.Read Mail.Read Files.ReadWrite.All Sites.Read.All");
        c.put("roles", List.of("Reader", "Contributor", "BackupOperator", "AuditLogViewer", "KeyVaultUser"));
        c.put("groups", adGroups(25));
        c.put("xms_cc", List.of("CP1"));
        c.put("ver", "2.0");
        return c;
    }

    private static List<String> adGroups(int n) {
        String[] names = {
                "eng-platform-us", "eng-crypto-team", "sec-incident-response", "it-helpdesk-tier2",
                "fin-payroll-readers", "hr-benefits-admin", "ops-oncall-primary", "data-analytics-core",
                "cloud-infra-admins", "net-firewall-change", "dev-api-gateway", "qa-release-signoff",
                "arch-review-board", "compliance-fedramp", "audit-log-readers", "vpn-remote-access",
                "gov-cac-required", "pki-cert-issuers", "kms-key-operators", "db-prod-readonly",
                "ml-training-users", "backup-restore-ops", "legal-ediscovery", "proj-quantum-migration",
                "all-employees-us"
        };
        return java.util.Arrays.stream(names).limit(n)
                .map(g -> "CN=" + g + ",OU=Groups,DC=corp,DC=example,DC=com")
                .toList();
    }
}
