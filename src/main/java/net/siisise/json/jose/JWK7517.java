package net.siisise.json.jose;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import net.siisise.io.BASE64;
import net.siisise.json.JSON;
import net.siisise.json.JSONArray;
import net.siisise.json.JSONObject;
import net.siisise.json.JSONString;
import net.siisise.security.ec.EdWards;
import net.siisise.security.ec.EdWards25519;
import net.siisise.security.ec.EdWards448;
import net.siisise.security.ec.EllipticCurve;
import net.siisise.security.key.ECDSAPrivateKey;
import net.siisise.security.key.ECDSAPublicKey;
import net.siisise.security.key.EdDSAPrivateKey;
import net.siisise.security.key.EdDSAPublicKey;
import net.siisise.security.sign.ECDSA;

/**
 * RFC 7517 JSON Web Keys.
 * JSON形式で鍵管理.
 */
public class JWK7517 {
    
    JSONArray keyList;
    JSONObject keyMap;
    
    /**
     * RSA公開鍵の登録.
     * 
     * @param kid
     * @param key RSA公開鍵 
     */
    public void setKey(String kid, RSAPublicKey key) {
        JSONObject pub = toJwk(key);
        keyMap.put(kid, pub);
    }
    
    public void setKey(String kid, RSAPrivateKey key) {
        JSONObject prv = toJwk(key);
        keyMap.put(kid, prv);
    }
    
    public void setKey(String kid, ECPublicKey key) {
        JSONObject pub = toJwk(key);
        keyMap.put(kid, pub);
    }

    public void setKey(String kid, ECPrivateKey key) {
        JSONObject pub = toJwk(key);
        keyMap.put(kid, pub);
    }

    public void setKey(String kid, EdDSAPublicKey key) {
        JSONObject pub = toJwk(key);
        keyMap.put(kid, pub);
    }

    public void setKey(String kid, EdDSAPrivateKey key) {
        JSONObject pub = JWK7517.toJwk(key);
        keyMap.put(kid, pub);
    }

    /**
     * HMAC, password で使える?
     * @param kid
     * @return 
     */
    private JSONObject selectKey(String kid) {
        for ( Object k : keyList ) {
            JSONObject key = (JSONObject)k;
            if ( kid.equals(key.get("kid"))) {
                return key;
            }
        }
        throw new SecurityException("鍵なし");
    }
    
    static JSONObject toJwk(PrivateKey key) {
        if ( key instanceof RSAPrivateKey ) {
            return toJwk((RSAPrivateKey)key);
        } else 
        if ( key instanceof ECPrivateKey ) {
            return toJwk((ECPrivateKey)key);
        } else 
        if ( key instanceof EdDSAPrivateKey ) {
            return toJwk((EdDSAPrivateKey)key);
        } else {
            throw new UnsupportedOperationException();
        }
    }

    static JSONObject toJwk(PublicKey key) {
        if ( key instanceof RSAPublicKey ) {
            return toJwk((RSAPublicKey)key);
        } else 
        if ( key instanceof ECPrivateKey ) {
            return toJwk((ECPublicKey)key);
        } else 
        if ( key instanceof EdDSAPublicKey ) {
            return toJwk((EdDSAPublicKey)key);
        } else {
            throw new UnsupportedOperationException();
        }
    }

    /**
     * RSA秘密鍵のJSON Keyへの変換
     * @param key ASN.1鍵
     * @return JSON鍵
     */
    static JSONObject toJwk(RSAPrivateKey key) {
        JSONObject jwk = new JSONObject();
        jwk.put("kty", "RSA");
        String n = I2Hex(key.getModulus());
        String d = I2Hex( key.getPrivateExponent() );
        jwk.put("n", n);
        jwk.put("d", d);
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey crt = (RSAPrivateCrtKey) key;
            jwk.put("e", I2Hex(crt.getPublicExponent()));
            jwk.put("p", I2Hex(crt.getPrimeP()));
            jwk.put("q", I2Hex(crt.getPrimeQ()));
            jwk.put("dp", I2Hex(crt.getPrimeExponentP()));
            jwk.put("dq", I2Hex(crt.getPrimeExponentQ()));
            jwk.put("qi", I2Hex(crt.getCrtCoefficient()));
        }
        return jwk;
    }

    /**
     * 
     * @param key Java RSA公開鍵
     * @return JSON公開鍵
     */
    static JSONObject toJwk(RSAPublicKey key) {
        JSONObject jwk = new JSONObject();
        String n = I2Hex(key.getModulus());
        String e = I2Hex( key.getPublicExponent());
        jwk.put("n", n);
        jwk.put("e", e);
        return jwk;
    }
    
    /**
     * EC鍵変換.
     * 予定は未定.
     * @return JSON
     */
    static JSONObject toJwk(ECPrivateKey key) {
        ECDSAPrivateKey ek = ECDSA.toECDSAKey(key);
        EllipticCurve.ECCurvep curve = ek.getCurve();

        int plen = (curve.p.bitLength()+7)/8;
        int nlen = (curve.n.bitLength()+7)/8;
        BigInteger d = ek.getS();
        EllipticCurve.Point Y = curve.xG(d);
        
        JSONObject jwk = new JSONObject();
        jwk.put("kty","EC");
//        jwk.put("use", "sig");
        jwk.put("crv",toCrvName(curve));
        jwk.put("x", I2Hex(Y.getX(), plen));
        jwk.put("y", I2Hex(Y.getY(), plen));
        jwk.put("d", I2Hex(d, nlen));
        return jwk;
    }

    /**
     * EC鍵変換.
     * 予定は未定.
     * @return 
     */
    static JSONObject toJwk(ECPublicKey key) {
        ECDSAPublicKey pub = ECDSA.toECDSAKey(key);
        EllipticCurve.ECCurvep curve = pub.getCurve();

        int plen = (curve.p.bitLength()+7)/8;
        EllipticCurve.Point Y = pub.getY();

        JSONObject jwk = new JSONObject();
        jwk.put("kty","EC");
        jwk.put("crv", toCrvName(curve));
        jwk.put("x", I2Hex(Y.getX(), plen));
        jwk.put("y", I2Hex(Y.getY(), plen));
        return jwk;
    }

    static String toCrvName(EllipticCurve curve) {
        String crv;
/*
        if (curve instanceof EdWards25519) {
            crv = "Ed25519";
        } else if (curve instanceof EdWards448) {
            crv = "Ed448";
        } else
//*/
        if (curve.equals(EllipticCurve.P256)) {
            crv = "P-256";
        } else if (curve.equals(EllipticCurve.P384)) {
            crv = "P-384";
        } else if (curve.equals(EllipticCurve.P521)) {
            crv = "P-521";
        } else if (curve.equals(EllipticCurve.secp256k1)) {
            crv = "secp256k1";
        } else {
            throw new UnsupportedOperationException();
        }
        return crv;
    }

    static String toCrvName(EdWards curve) {
        String crv;
        if (curve instanceof EdWards25519) {
            crv = "Ed25519";
        } else if (curve instanceof EdWards448) {
            crv = "Ed448";
        } else {
            throw new UnsupportedOperationException();
        }
        return crv;
    }
    
    static JSONObject toJwk(EdDSAPrivateKey key) {
        EdWards ed = key.getCurve();
        String crv = toCrvName(ed);
        JSONObject jwk = new JSONObject();
        jwk.put("kty","OKP"); // Octet Key Pair
        jwk.put("crv", crv);
        String prv = ((JSONString)key.rebind(JSON.JSON)).toString();
        jwk.put("d", prv);
        jwk.put("x", B2Hex(key.getA()));
        return jwk;
    }

    static JSONObject toJwk(EdDSAPublicKey key) {
        EdWards ed = key.getCurve();
        String crv = toCrvName(ed);
        JSONObject jwk = new JSONObject();
        jwk.put("kty","OKP"); // Octet Key Pair
        jwk.put("crv", crv);
        jwk.put("x", B2Hex(key.getA()));
        return jwk;
    }

    /**
     * BASE64URL
     * @param n 正の整数
     * @return 
     */
    static String I2Hex(BigInteger n) {
        byte[] d = n.toByteArray();
        if (d[0] == 0) {
            byte[] p = new byte[d.length - 1];
            System.arraycopy(d, 1, p, 0, p.length);
            d = p;
        }
        return B2Hex(d);
    }
    
    static String I2Hex(BigInteger n, int len) {
        byte[] d = net.siisise.ietf.pkcs1.PKCS1.I2OSP(n, len);
        return B2Hex(d);
    }

    static String B2Hex(byte[] d) {
        BASE64 b64 = new BASE64(BASE64.URL, 0);
        return b64.encode(d);
    }
}
