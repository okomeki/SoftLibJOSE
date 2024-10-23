package net.siisise.json.jose;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import net.siisise.io.BASE64;
import net.siisise.json.JSON;
import net.siisise.json.JSONObject;
import net.siisise.security.block.ES;
import net.siisise.security.block.RSAES;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;
import net.siisise.security.mode.StreamAEAD;

/**
 * JSON Web Encryption 暗号化.
 * AES-GCM など
 * JWE Compact Serialization
 * JWE JSON Serialization
 * RFC 7516 JSON Web Encryption (JWE)
 * RFC 7159
 * RFC 8259 The JavaScript Object Notation (JSON) Data Interchange Format
 */
public class JWE7516 {

    private static final Charset UTF8 = StandardCharsets.UTF_8;

    private JSONObject jweProtectedHeader = new JSONObject();
    private JSONObject jweSharedUnprotectedHeader;
    private JSONObject jwePerRecipientUnprotectedHeader;
    private byte[] cek;
    private byte[] jweEncryptedKey;
    private byte[] jweInitializationVector;
    private byte[] jweCiphertext;
    private byte[] jweAuthenticationTag;
    private byte[] jweAAD;

    private final SecureRandom srnd;
    RSAMiniPrivateKey key;
    RSAPublicKey pub;

    public JWE7516() {
        try {
            srnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            throw new SecurityException(ex);
        }
    }

    public void init(RSAMiniPrivateKey key) {
        this.key = key;
    }

    public void init(RSAPublicKey pub) {
        this.pub = pub;
    }

    /**
     * JWE compact形式.
     * JWE Sjared Unprotected Jeader または JWE Per-Recipient Unprotected Header は使用されない
     * @param payload
     * @return
     * @throws NoSuchAlgorithmException
     */
    public String compact(byte[] payload) throws NoSuchAlgorithmException {
        // 変換するだけ
        JSONObject json = json(payload);
        StringBuilder jwe = new StringBuilder();
        jwe.append(json.get("protected")); // JWE Protected Header
        jwe.append(".");
        jwe.append(json.get("encrypted_key")); // JWE Encrypted Key
        jwe.append(".");
        jwe.append(json.get("iv")); // JWE Initialization Vector
        jwe.append(".");
        jwe.append(json.get("ciphertext")); // JWE Ciphertext
        jwe.append(".");
        jwe.append(json.get("tag")); // JWE Authentication Tag
        return jwe.toString();
    }

    /**
     * JWE JSON Serialization.
     * aad なし
     * @param payload メッセージ本体
     * @return JWE 暗号化JSON
     */
    public JSONObject json(byte[] payload) {
        return json(payload, new byte[0]);
    }

    /**
     * JWE JSON Serialization
     *
     * @param payload データ本体
     * @param aad JWE AAD 暗号化しない付加情報
     * @return JWE Encrypted JSON
     */
    public JSONObject json(byte[] payload, byte[] aad) {
//        jweProtectedHeader = new JSONObject();
        jweProtectedHeader.put("alg", "RSA-OAEP"); // cek を暗号化するアルゴリズム 仮指定 JWE 7516 3.3. Example JWA 4.1.
        jweProtectedHeader.put("enc", "A256GCM"); // 暗号文と認証タグを生成するためのAEADアルゴリズム 仮指定 JWE 7516 3.3. JWA 5.1.
        
        // jku 公開鍵を指すもの JWSと同じ(暗号化した公開鍵)
//        jwsProtectedHeader.put("jku",); // JWK 4.1.4. JWS 4.1.2.
//        jwsProtectedHeader.put("jwk",); // JWK 4.1.5. JWS 4.1.3.
//        jwsProtectedHeader.put("kid",); // JWK 4.1.6. JWS 4.1.4.
//        jwsProtectedHeader.put("x5u",); // JWK 4.1.7. JWS 4.1.5. 証明書
//        jwsProtectedHeader.put("x5c",); // JWK 4.1.8. JWS 4.1.6. 証明書チェーン JWS付録B
//        jwsProtectedHeader.put("x5t",); // JWK 4.1.9. JWS 4.1.7. 証明書SHA1フィンガープリント
//        jwsProtectedHeader.put("x5t#256",); // JWK 4.1.10. JWS 4.1.8. 証明書SHA256フィンガープリント
//        jwsProtectedHeader.put("typ",); // JWK 4.1.11. JWS 4.1.9. JWTの
//        jwsProtectedHeader.put("cty",); // JWK 4.1.12. JWS 4.1.10. Content-Type
//        jwsProtectedHeader.put("crit",); // JWK 4.1.13. JWS 4.1.11.

        StreamAEAD aead = JWA7518.blockAlg((String) jweProtectedHeader.get("enc"));
        int[] lengs = aead.getParamLength();
        
        cek = new byte[(lengs[0]+7)/8]; // cek鍵長の計算
        srnd.nextBytes(cek);

        // jweEncryptedKey alg で指定した方法でCEKを暗号化する
        // RSA鍵を使用
        //   RSA1_5
        //   RSAES-PKCS1-v1_5
        //   RSAES-OAEP
        //   RSAES-OAEP-256
        // AES鍵を使用
        //   A128KW
        //   A192KW
        //   A256KW
        // 暗号なし
        //   dir
        // 
        //   ECDH-ES
        //   ECDH-ES+A128KW
        //   ECDH-ES+A192KW
        //   ECDH-ES+A256KW
        // AES鍵
        //   A128GCMKW
        //   A192GCMKW
        //   A256GCMKW
        // パスワード
        //   PBES2+HS256+A128KW
        //   PBES2+HS384+A192KW
        //   PBES2+HS512+A256KW
        JWA7518 jwa = new JWA7518();
        
        RSAES es = (RSAES)jwa.toES(jweProtectedHeader); // alg
        // 鍵の指定方法を
        es.init(pub);
        jweEncryptedKey = es.encrypt(cek);
        if ( es instanceof JWA7518.JWA_ES) {
            ((JWA7518.JWA_ES)es).genHeader(jweProtectedHeader);
        }

        jweInitializationVector = new byte[(lengs[1]+7)/8];
        srnd.nextBytes(jweInitializationVector);

        aead.init(cek, jweInitializationVector, aad);
        //StreamAEAD gcm = JWA7518.algo((String) jweProtectedHeader.get("enc"), cek, jweInitializationVector, aad);
        jweCiphertext = aead.encrypt(payload);
        jweAuthenticationTag = aead.doFinalEncrypt(); // または tag();

        BASE64 b64 = new BASE64(BASE64.URL, 0);
        JSONObject json = new JSONObject();
        // JWE Protected Header                 JWE保護ヘッダー
        json.put("protected", b64.encode(jweProtectedHeader.toJSON().getBytes(UTF8)));
        // JWE Shard Unprotected Header         JWE共有非保護ヘッダー (JWE JSON Serializationのみ)
        if (jweSharedUnprotectedHeader != null) {
            json.put("unprotected", jweSharedUnprotectedHeader);
        }
        // JOSE Header
        // JWE Per-Recipient Unprotected Header JWE受信者毎非保護ヘッダー (JWE JSON Serializationのみ)
        if (jwePerRecipientUnprotectedHeader != null) {
            json.put("header", jwePerRecipientUnprotectedHeader);
        }

        // JWE Encrypted Key
        json.put("encrypted_key", b64.encode(jweEncryptedKey));
        // JWE Initialization Vector
        json.put("iv", b64.encode(jweInitializationVector));
        // JWE Ciphertext
        json.put("ciphertext", b64.encode(jweCiphertext));
        // JWE Authentication Tag
        json.put("tag", b64.encode(jweAuthenticationTag));
        // JWE AAD
        if (aad != null) { // ToDo: null と [0] を区別する?
            json.put("aad", b64.encode(aad));
        }
        return json;
    }

    /**
     * JWE Compact Serialization からJWE JSON Serializationに戻す.
     * @param jweCompact
     * @return 
     */
    private JSONObject deCompact(String jweCompact) {
        String[] sp = jweCompact.split("\\.");
        if (sp.length != 5) {
            throw new IllegalStateException();
        }
        JSONObject jwe = new JSONObject();
        jwe.put("protected", sp[0]);
        jwe.put("encrypted_key", sp[1]);
        jwe.put("iv", sp[2]);
        jwe.put("ciphertext", sp[3]);
        jwe.put("tag", sp[4]);
        return jwe;
    }

    /**
     * JWE JSON Serialization の decode と validation.
     * @param jwe
     * @return 
     */
    public byte[] validate(JSONObject jwe) {
        BASE64 b64 = new BASE64(BASE64.URL, 0);
        jweProtectedHeader = (JSONObject) JSON.parseWrap(b64.decode((String) jwe.get("protected")));
        jweSharedUnprotectedHeader = (JSONObject) jwe.getJSON("unprotected");
        jwePerRecipientUnprotectedHeader = (JSONObject) jwe.getJSON("header");

        jweEncryptedKey = b64.decode((String) jwe.get("encrypted_key"));
        jweInitializationVector = b64.decode((String) jwe.get("iv"));
        jweCiphertext = b64.decode((String) jwe.get("ciphertext"));
        jweAuthenticationTag = b64.decode((String) jwe.get("tag"));
        String aadenc = (String) jwe.get("aad");
        if (aadenc != null) {
            jweAAD = b64.decode(aadenc);
        } else {
            jweAAD = new byte[0];
        }
        
        JWA7518 jwa = new JWA7518();

        ES es = jwa.toES(jweProtectedHeader);
        if ( es instanceof JWA7518.JWA_ES) {
            JWA7518.JWA_ES jes = (JWA7518.JWA_ES)es;
            jes.readHeader(jweProtectedHeader);
        } else if ( es instanceof RSAES ) {
            ((RSAES)es).init(key);
        }
        cek = es.decrypt( jweEncryptedKey);

        StreamAEAD aead = JWA7518.algo((String) jweProtectedHeader.get("enc"), cek, jweInitializationVector, jweAAD);
        byte[] payload = aead.decrypt(jweCiphertext);
        byte[] tag = aead.doFinalDecrypt(jweAuthenticationTag);
        if (tag.length != 0) {
            throw new IllegalStateException();
        }
        return payload;
    }

    public byte[] validateCompact(String compact) {
        return validate(deCompact(compact));
    }
}
