package org.pqjose.jose;

import org.pqjose.core.Keys;
import org.pqjose.core.SigAlg;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Public-key JWK members per algorithm.
 *
 * Classical algorithms use RFC 7517/7518 kty values. ML-DSA and SLH-DSA use the
 * draft "AKP" (Algorithm Key Pair) key type from draft-ietf-cose-dilithium: the raw
 * public key as a single base64url "pub" member with "alg" carrying the parameter set.
 */
public final class Jwks {

    private Jwks() {}

    public static Map<String, Object> publicJwk(SigAlg alg, PublicKey pub, String kid) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        switch (alg) {
            case RS256 -> {
                RSAPublicKey rsa = (RSAPublicKey) pub;
                jwk.put("kty", "RSA");
                jwk.put("n", Keys.b64url(unsigned(rsa.getModulus())));
                jwk.put("e", Keys.b64url(unsigned(rsa.getPublicExponent())));
            }
            case ES256 -> {
                ECPublicKey ec = (ECPublicKey) pub;
                jwk.put("kty", "EC");
                jwk.put("crv", "P-256");
                jwk.put("x", Keys.b64url(fixedLength(ec.getW().getAffineX(), 32)));
                jwk.put("y", Keys.b64url(fixedLength(ec.getW().getAffineY(), 32)));
            }
            case ED25519 -> {
                jwk.put("kty", "OKP");
                jwk.put("crv", "Ed25519");
                jwk.put("x", Keys.b64url(Keys.rawPublicKey(pub)));
            }
            default -> {
                jwk.put("kty", "AKP");
                jwk.put("alg", alg.joseName);
                jwk.put("pub", Keys.b64url(Keys.rawPublicKey(pub)));
            }
        }
        jwk.put("use", "sig");
        jwk.put("kid", kid);
        return jwk;
    }

    private static byte[] unsigned(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            byte[] trimmed = new byte[b.length - 1];
            System.arraycopy(b, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return b;
    }

    private static byte[] fixedLength(BigInteger v, int len) {
        byte[] b = unsigned(v);
        if (b.length == len) {
            return b;
        }
        byte[] out = new byte[len];
        System.arraycopy(b, 0, out, len - b.length, b.length);
        return out;
    }
}
