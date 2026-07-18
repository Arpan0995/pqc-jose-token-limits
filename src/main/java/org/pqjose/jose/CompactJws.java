package org.pqjose.jose;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.pqjose.core.Keys;
import org.pqjose.core.SigAlg;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Map;

/**
 * Byte-exact compact JWS construction over java.security.Signature.
 *
 * The experiments build tokens here rather than through a JOSE library so that header
 * contents (including the draft "AKP" JWK type, which libraries do not yet parse) and
 * every byte of the serialization are under the experiment's control. Library
 * integration is demonstrated separately in NimbusJcaSigner/NimbusJcaVerifier.
 */
public final class CompactJws {

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private CompactJws() {}

    public record Token(String compact, int headerB64, int payloadB64, int sigB64, int rawSigBytes) {
        public int totalBytes() {
            return compact.length();   // compact JWS is pure ASCII
        }
    }

    public static String toJson(Map<String, Object> map) {
        return GSON.toJson(map);
    }

    public static Token sign(SigAlg alg, String providerName, PrivateKey priv,
                             Map<String, Object> header, Map<String, Object> claims) throws Exception {
        String h = Keys.b64url(toJson(header).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String p = Keys.b64url(toJson(claims).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] signingInput = Keys.ascii(h + "." + p);

        Signature sig = alg.newSignature(providerName);
        sig.initSign(priv);
        sig.update(signingInput);
        byte[] rawSig = sig.sign();

        String s = Keys.b64url(rawSig);
        return new Token(h + "." + p + "." + s, h.length(), p.length(), s.length(), rawSig.length);
    }

    public static boolean verify(SigAlg alg, String providerName, PublicKey pub, String compact) throws Exception {
        int firstDot = compact.indexOf('.');
        int lastDot = compact.lastIndexOf('.');
        byte[] signingInput = Keys.ascii(compact.substring(0, lastDot));
        byte[] rawSig = java.util.Base64.getUrlDecoder().decode(compact.substring(lastDot + 1));
        if (firstDot == lastDot) {
            throw new IllegalArgumentException("not a compact JWS");
        }
        Signature sig = alg.newSignature(providerName);
        sig.initVerify(pub);
        sig.update(signingInput);
        return sig.verify(rawSig);
    }
}
