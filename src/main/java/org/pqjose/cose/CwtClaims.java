package org.pqjose.cose;

import com.upokecenter.cbor.CBORObject;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * JWT claim set -> CWT claims map (RFC 8392).
 *
 * Registered claims move to integer keys (iss=1, sub=2, aud=3, exp=4, nbf=5, iat=6,
 * cti=7; scope=9 per RFC 9200). jti becomes cti with the UUID as a 16-byte binary
 * string, the CWT-idiomatic form. Claims without a CWT registration (OIDC profile
 * claims, vendor claims like groups/roles/tid) keep their text keys — CBOR maps
 * take mixed keys, and this mirrors what a real deployment could actually do.
 */
public final class CwtClaims {

    private static final Map<String, Integer> REGISTERED = Map.of(
            "iss", 1, "sub", 2, "aud", 3, "exp", 4, "nbf", 5, "iat", 6, "scope", 9);

    private CwtClaims() {}

    public static CBORObject fromJwtClaims(Map<String, Object> claims) {
        CBORObject map = CBORObject.NewMap();
        for (Map.Entry<String, Object> e : claims.entrySet()) {
            if (e.getKey().equals("jti")) {
                map.Add(CBORObject.FromObject(7), CBORObject.FromObject(uuidBytes((String) e.getValue())));
                continue;
            }
            Integer key = REGISTERED.get(e.getKey());
            CBORObject label = key != null ? CBORObject.FromObject((int) key)
                    : CBORObject.FromObject(e.getKey());
            map.Add(label, toCbor(e.getValue()));
        }
        return map;
    }

    private static CBORObject toCbor(Object v) {
        if (v instanceof String s) {
            return CBORObject.FromObject(s);
        }
        if (v instanceof Long l) {
            return CBORObject.FromObject((long) l);
        }
        if (v instanceof Integer i) {
            return CBORObject.FromObject((int) i);
        }
        if (v instanceof Boolean b) {
            return CBORObject.FromObject((boolean) b);
        }
        if (v instanceof List<?> list) {
            CBORObject arr = CBORObject.NewArray();
            for (Object item : list) {
                arr.Add(toCbor(item));
            }
            return arr;
        }
        throw new IllegalArgumentException("unsupported claim type: " + v.getClass());
    }

    private static byte[] uuidBytes(String uuid) {
        try {
            UUID u = UUID.fromString(uuid);
            ByteBuffer buf = ByteBuffer.allocate(16);
            buf.putLong(u.getMostSignificantBits());
            buf.putLong(u.getLeastSignificantBits());
            return buf.array();
        } catch (IllegalArgumentException notAUuid) {
            return uuid.getBytes(StandardCharsets.UTF_8);
        }
    }
}
