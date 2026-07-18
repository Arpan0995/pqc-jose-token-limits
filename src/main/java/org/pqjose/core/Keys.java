package org.pqjose.core;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;

/** Key encoding helpers shared by JWK building and size accounting. */
public final class Keys {

    private Keys() {}

    /** Raw public-key bytes: the SubjectPublicKeyInfo BIT STRING contents. */
    public static byte[] rawPublicKey(PublicKey pub) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pub.getEncoded());
        return spki.getPublicKeyData().getOctets();
    }

    /** Short key id: first 8 bytes of SHA-256 over the SPKI, base64url. */
    public static String kid(PublicKey pub) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(pub.getEncoded());
            byte[] head = new byte[8];
            System.arraycopy(digest, 0, head, 0, 8);
            return b64url(head);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }
}
