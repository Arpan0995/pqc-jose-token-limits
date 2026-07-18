package org.pqjose;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.pqjose.core.Providers;
import org.pqjose.core.SigAlg;
import org.pqjose.jose.CompactJws;
import org.pqjose.jose.NimbusJcaSigner;
import org.pqjose.jose.NimbusJcaVerifier;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class RoundTripTest {

    @BeforeAll
    static void setUp() {
        Providers.install();
    }

    /** Unmodified Nimbus stack signs and verifies every algorithm through the custom provider classes. */
    @ParameterizedTest
    @EnumSource(SigAlg.class)
    void nimbusRoundTrip(SigAlg alg) throws Exception {
        assumeTrue(alg.availableProviders().contains(Providers.BC), "BC does not offer " + alg.joseName);
        KeyPair kp = alg.generateKeyPair(Providers.BC);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(alg.joseName)).keyID("test").build();
        JWSObject jws = new JWSObject(header, new Payload("{\"sub\":\"alice\"}"));
        jws.sign(new NimbusJcaSigner(alg, Providers.BC, kp.getPrivate()));

        JWSObject parsed = JWSObject.parse(jws.serialize());
        assertTrue(parsed.verify(new NimbusJcaVerifier(alg, Providers.BC, kp.getPublic())));

        // tampered payload must fail
        String[] parts = jws.serialize().split("\\.");
        String tampered = parts[0] + "." + com.nimbusds.jose.util.Base64URL.encode("{\"sub\":\"mallory\"}") + "." + parts[2];
        assertFalse(JWSObject.parse(tampered).verify(new NimbusJcaVerifier(alg, Providers.BC, kp.getPublic())));
    }

    /** ML-DSA token signed via BC verifies under the JDK 24 built-in provider (JEP 497). */
    @Test
    void mlDsaCrossProviderVerify() throws Exception {
        SigAlg alg = SigAlg.ML_DSA_65;
        assumeTrue(alg.availableProviders().contains("SUN"), "JDK provider lacks ML-DSA");

        KeyPair bcKp = alg.generateKeyPair(Providers.BC);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "JWT");
        header.put("alg", alg.joseName);
        CompactJws.Token token = CompactJws.sign(alg, Providers.BC, bcKp.getPrivate(),
                header, Map.of("sub", "alice"));

        PublicKey sunPub = sunKeyFactory().generatePublic(
                new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));
        assertTrue(CompactJws.verify(alg, "SUN", sunPub, token.compact()));
    }

    private static KeyFactory sunKeyFactory() throws Exception {
        try {
            return KeyFactory.getInstance("ML-DSA-65", "SUN");
        } catch (Exception e) {
            return KeyFactory.getInstance("ML-DSA", "SUN");
        }
    }
}
