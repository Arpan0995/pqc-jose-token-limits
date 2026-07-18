package org.pqjose.core;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;

/** Self-signed leaf certificates for the x5c header variant. */
public final class X5c {

    private X5c() {}

    /** DER bytes of a self-signed certificate over the given key pair, signed with the same algorithm. */
    public static byte[] selfSigned(SigAlg alg, KeyPair kp) throws Exception {
        Providers.install();
        X500Name dn = new X500Name("CN=as.example.gov, O=Example Authorization Server, C=US");
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(now), new Date(now - 3_600_000L),
                new Date(now + 365L * 24 * 3_600_000L), dn, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(alg.x509SigAlgName())
                .setProvider(Providers.BC)
                .build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return holder.getEncoded();
    }
}
