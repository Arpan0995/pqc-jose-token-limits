package org.pqjose.jose;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.pqjose.core.SigAlg;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Set;

/** Verification counterpart of NimbusJcaSigner. */
public class NimbusJcaVerifier implements JWSVerifier {

    private final SigAlg alg;
    private final String providerName;
    private final PublicKey publicKey;
    private final JCAContext jcaContext = new JCAContext();

    public NimbusJcaVerifier(SigAlg alg, String providerName, PublicKey publicKey) {
        this.alg = alg;
        this.providerName = providerName;
        this.publicKey = publicKey;
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
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
        if (!header.getAlgorithm().getName().equals(alg.joseName)) {
            return false;
        }
        try {
            Signature sig = alg.newSignature(providerName);
            sig.initVerify(publicKey);
            sig.update(signingInput);
            return sig.verify(signature.decode());
        } catch (Exception e) {
            throw new JOSEException(alg.joseName + " verification failed", e);
        }
    }
}
