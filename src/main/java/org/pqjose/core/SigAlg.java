package org.pqjose.core;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

/**
 * The signature algorithms under study.
 *
 * JOSE "alg" values: RFC 7518 for the classical baselines; the ML-DSA values are the
 * RFC 9964 registrations ("ML-DSA-44/65/87", kty "AKP"); the SLH-DSA values follow
 * draft-ietf-cose-sphincs-plus, still a draft as of July 2026, and are pinned in
 * docs/EXPERIMENT-DESIGN.md.
 */
public enum SigAlg {

    RS256("RS256", Family.CLASSICAL, new String[]{"SHA256withRSA"}),
    ES256("ES256", Family.CLASSICAL, new String[]{"SHA256withECDSAinP1363Format", "SHA256withPLAIN-ECDSA"}),
    ED25519("EdDSA", Family.CLASSICAL, new String[]{"Ed25519"}),

    ML_DSA_44("ML-DSA-44", Family.PQ, new String[]{"ML-DSA-44", "ML-DSA"}),
    ML_DSA_65("ML-DSA-65", Family.PQ, new String[]{"ML-DSA-65", "ML-DSA"}),
    ML_DSA_87("ML-DSA-87", Family.PQ, new String[]{"ML-DSA-87", "ML-DSA"}),

    SLH_DSA_128S("SLH-DSA-SHA2-128s", Family.PQ, new String[]{"SLH-DSA-SHA2-128S"}),
    SLH_DSA_128F("SLH-DSA-SHA2-128f", Family.PQ, new String[]{"SLH-DSA-SHA2-128F"});

    public enum Family { CLASSICAL, PQ }

    public final String joseName;
    public final Family family;
    private final String[] jcaCandidates;

    SigAlg(String joseName, Family family, String[] jcaCandidates) {
        this.joseName = joseName;
        this.family = family;
        this.jcaCandidates = jcaCandidates;
    }

    /** Providers on this JVM that implement the algorithm. */
    public List<String> availableProviders() {
        return Providers.signatureProviders(jcaCandidates);
    }

    public Signature newSignature(String providerName) throws Exception {
        String jcaName = Providers.resolveJcaName(providerName, jcaCandidates);
        if (jcaName == null) {
            throw new IllegalStateException(joseName + " not offered by provider " + providerName);
        }
        return Signature.getInstance(jcaName, providerName);
    }

    /** X.509 signature-algorithm name for BC's ContentSigner (x5c chain building). */
    public String x509SigAlgName() {
        return switch (this) {
            case RS256 -> "SHA256withRSA";
            case ES256 -> "SHA256withECDSA";   // DER form: X.509 uses DER, JOSE uses P1363
            case ED25519 -> "Ed25519";
            default -> jcaCandidates[0];
        };
    }

    public KeyPair generateKeyPair(String providerName) throws Exception {
        Providers.install();
        return switch (this) {
            case RS256 -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", providerName);
                kpg.initialize(2048);
                yield kpg.generateKeyPair();
            }
            case ES256 -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", providerName);
                kpg.initialize(new ECGenParameterSpec("secp256r1"));
                yield kpg.generateKeyPair();
            }
            case ED25519 -> KeyPairGenerator.getInstance("Ed25519", providerName).generateKeyPair();
            default -> {
                // PQ key-pair generators are registered under the parameter-set name in
                // both BC and the JDK (JEP 497).
                KeyPairGenerator kpg = keyPairGenerator(providerName);
                yield kpg.generateKeyPair();
            }
        };
    }

    private KeyPairGenerator keyPairGenerator(String providerName) throws Exception {
        Exception last = null;
        for (String name : jcaCandidates) {
            try {
                return KeyPairGenerator.getInstance(name, providerName);
            } catch (Exception e) {
                last = e;
            }
        }
        throw last;
    }
}
