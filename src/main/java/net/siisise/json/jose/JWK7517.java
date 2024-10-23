package net.siisise.json.jose;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import net.siisise.io.BASE64;
import net.siisise.json.JSONArray;
import net.siisise.json.JSONObject;

/**
 *
 */
public class JWK7517 {
    
    JSONArray keyList;
    JSONObject keyMap;
    
    public void setRSAKey(String kid, RSAPublicKey key) {
        JSONObject pub = rsaPublicToJwk(key);
        keyMap.put(kid, pub);
    }
    
    public void setRSAKey(String kid, RSAPrivateKey key) {
        JSONObject prv = rsaPrivateToJwk(key);
        keyMap.put(kid, prv);
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

    static JSONObject rsaPrivateToJwk(RSAPrivateKey key) {
        JSONObject jwk = new JSONObject();
        String n = encodeBigHex(key.getModulus());
        String d = encodeBigHex( key.getPrivateExponent() );
        jwk.put("n", n);
        jwk.put("d", d);
        return jwk;
    }

    static JSONObject rsaPublicToJwk(RSAPublicKey key) {
        JSONObject jwk = new JSONObject();
        String n = encodeBigHex(key.getModulus());
        String e = encodeBigHex( key.getPublicExponent());
        jwk.put("n", n);
        jwk.put("e", e);
        return jwk;
    }

    /**
     * BASE64URL
     * @param n 正の整数
     * @return 
     */
    static String encodeBigHex(BigInteger n) {
        byte[] d = n.toByteArray();
        if (d[0] == 0) {
            byte[] p = new byte[d.length - 1];
            System.arraycopy(d, 1, p, 0, p.length);
            d = p;
        }
        BASE64 b64 = new BASE64(BASE64.URL, 0);
        return b64.encode(d);
    }

}
