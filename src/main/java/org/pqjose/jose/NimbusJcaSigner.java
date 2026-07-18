package org.pqjose.jose;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.pqjose.core.SigAlg;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.Set;

/**
 * Nimbus JWSSigner backed by java.security.Signature, adding the draft ML-DSA and
 * SLH-DSA JOSE algorithms (and JCA-native EdDSA) to an unmodified Nimbus stack.
 * This is the integration path an application would actually deploy.
 */
public class NimbusJcaSigner implements JWSSigner {

    private final SigAlg alg;
    private final String providerName;
    private final PrivateKey privateKey;
    private final JCAContext jcaContext = new JCAContext();

    public NimbusJcaSigner(SigAlg alg, String providerName, PrivateKey privateKey) {
        this.alg = alg;
        this.providerName = providerName;
        this.privateKey = privateKey;
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.parse(alg.joseName));
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        if (!header.getAlgorithm().getName().equals(alg.joseName)) {
            throw new JOSEException("Signer configured for " + alg.joseName
                    + " but header says " + header.getAlgorithm());
        }
        try {
            Signature sig = alg.newSignature(providerName);
            sig.initSign(privateKey);
            sig.update(signingInput);
            return Base64URL.encode(sig.sign());
        } catch (Exception e) {
            throw new JOSEException(alg.joseName + " signing failed", e);
        }
    }
}
