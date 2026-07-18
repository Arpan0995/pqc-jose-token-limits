package org.pqjose.cose;

import com.upokecenter.cbor.CBORObject;
import org.pqjose.core.SigAlg;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Byte-exact COSE_Sign1 (RFC 9052) construction over java.security.Signature,
 * mirroring CompactJws on the JOSE side.
 *
 * COSE alg identifiers: ES256=-7, EdDSA=-8, RS256=-257 (RFC 8812). The ML-DSA
 * values (-48/-49/-50) follow draft-ietf-cose-dilithium; the SLH-DSA values are
 * provisional draft-range placeholders pinned for this study. Final registry
 * numbers cannot change any conclusion: a small negative int costs 1-2 bytes
 * either way.
 */
public final class CoseSign1 {

    private CoseSign1() {}

    public record Signed(byte[] encoded, int protectedLen, int payloadLen, int sigLen) {}

    public static int coseAlgId(SigAlg alg) {
        return switch (alg) {
            case RS256 -> -257;
            case ES256 -> -7;
            case ED25519 -> -8;
            case ML_DSA_44 -> -48;
            case ML_DSA_65 -> -49;
            case ML_DSA_87 -> -50;
            case SLH_DSA_128S -> -51;
            case SLH_DSA_128F -> -52;
        };
    }

    public static Signed sign(SigAlg alg, String provider, PrivateKey priv,
                              byte[] kid, CBORObject claims) throws Exception {
        CBORObject protectedMap = CBORObject.NewMap();
        protectedMap.Add(CBORObject.FromObject(1), CBORObject.FromObject(coseAlgId(alg)));
        byte[] protectedBytes = protectedMap.EncodeToBytes();

        CBORObject unprotected = CBORObject.NewMap();
        unprotected.Add(CBORObject.FromObject(4), CBORObject.FromObject(kid));

        byte[] payload = claims.EncodeToBytes();
        byte[] toBeSigned = sigStructure(protectedBytes, payload);

        Signature sig = alg.newSignature(provider);
        sig.initSign(priv);
        sig.update(toBeSigned);
        byte[] rawSig = sig.sign();

        CBORObject coseSign1 = CBORObject.NewArray();
        coseSign1.Add(CBORObject.FromObject(protectedBytes));
        coseSign1.Add(unprotected);
        coseSign1.Add(CBORObject.FromObject(payload));
        coseSign1.Add(CBORObject.FromObject(rawSig));

        byte[] encoded = CBORObject.FromObjectAndTag(coseSign1, 18).EncodeToBytes();
        return new Signed(encoded, protectedBytes.length, payload.length, rawSig.length);
    }

    public static boolean verify(SigAlg alg, String provider, PublicKey pub, byte[] encoded) throws Exception {
        CBORObject obj = CBORObject.DecodeFromBytes(encoded);
        if (obj.HasMostOuterTag(18)) {
            obj = obj.UntagOne();
        }
        byte[] protectedBytes = obj.get(0).GetByteString();
        byte[] payload = obj.get(2).GetByteString();
        byte[] rawSig = obj.get(3).GetByteString();

        Signature sig = alg.newSignature(provider);
        sig.initVerify(pub);
        sig.update(sigStructure(protectedBytes, payload));
        return sig.verify(rawSig);
    }

    private static byte[] sigStructure(byte[] protectedBytes, byte[] payload) {
        CBORObject sigStruct = CBORObject.NewArray();
        sigStruct.Add(CBORObject.FromObject("Signature1"));
        sigStruct.Add(CBORObject.FromObject(protectedBytes));
        sigStruct.Add(CBORObject.FromObject(new byte[0]));   // external_aad
        sigStruct.Add(CBORObject.FromObject(payload));
        return sigStruct.EncodeToBytes();
    }
}
