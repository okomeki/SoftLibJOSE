package net.siisise.json.jose;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import net.siisise.ietf.pkcs5.PBKDF2;
import net.siisise.io.BASE64;
import net.siisise.io.PacketA;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.json.JSONObject;
import net.siisise.security.block.AES;
import net.siisise.security.block.ES;
import net.siisise.security.block.RSAES;
import net.siisise.security.block.RSAES_OAEP;
import net.siisise.security.block.RSAES_PKCS1_v1_5;
import net.siisise.security.digest.SHA256;
import net.siisise.security.digest.SHA384;
import net.siisise.security.digest.SHA512;
import net.siisise.security.key.AESKeyWrap;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;
import net.siisise.security.mac.HMAC;
import net.siisise.security.mac.MAC;
import net.siisise.security.mode.BlockAEAD;
import net.siisise.security.mode.GCM;
import net.siisise.security.mode.StreamAEAD;
import net.siisise.security.padding.EME;
import net.siisise.security.padding.MGF;
import net.siisise.security.padding.MGF1;
import net.siisise.security.sign.RSASSA_PKCS1_v1_5;
import net.siisise.security.sign.RSASSA_PSS;

/**
 * JWA アルゴリズム
 *
 * https://www.rfc-editor.org/rfc/rfc7518
 */
public class JWA7518 {

    /**
     * MessageDigestとMACが似ているのでまとめる.
     */
    interface DigestAndMAC {

        void init();

        void update(byte[] src);

        byte[] doFinal();

        default byte[] doFinal(byte[] src) {
            update(src);
            return doFinal();
        }
        
        default boolean verify(byte[] sign) {
            return Arrays.equals(sign, doFinal());
        }

        OBJECTIDENTIFIER oid();
    }

    class MD implements DigestAndMAC {

        final MessageDigest md;
        final OBJECTIDENTIFIER oid;

        MD(MessageDigest md, String oid) {
            this.md = md;
            this.oid = new OBJECTIDENTIFIER(oid);
        }

        @Override
        public void init() {
        }

        @Override
        public void update(byte[] src) {
            md.update(src);
        }

        @Override
        public byte[] doFinal() {
            return md.digest();
        }

        @Override
        public OBJECTIDENTIFIER oid() {
            return oid;
        }
    }

    class DMAC implements DigestAndMAC {

        net.siisise.security.mac.MAC mac;
        OBJECTIDENTIFIER oid;

        DMAC(net.siisise.security.mac.MAC mac, String oid) {
            this.mac = mac;
            this.oid = new OBJECTIDENTIFIER(oid);
        }

        public void init() {
        }

        @Override
        public void update(byte[] src) {
            mac.update(src);
        }

        @Override
        public byte[] doFinal() {
            return mac.sign();
        }

        @Override
        public OBJECTIDENTIFIER oid() {
            return oid;
        }
    }

    public DigestAndMAC alg() {
        throw new UnsupportedOperationException();
    }

    interface SignAlgorithm {

        void initPrivate(JSONObject jwk);
        void initPublic(JSONObject jwk);
        
        void update(byte[] data);
        byte[] sign(JSONObject jwk, byte[] data);
        byte[] sign();

        boolean verify(JSONObject jwk, byte[] data, byte[] sign);
        boolean verify(byte[] sign);
    }

    /**
     * RSASSA で使用するDigestの選択.
     * @param alg RSxxx または PSxxx
     * @return 対応するSHA-2 Hash
     */
    static MessageDigest toDigest(String alg) {
        String num = alg.substring(2);
        switch (num) {
            case "256":
                return new SHA256();
            case "384":
                return new SHA384();
            case "512":
                return new SHA512();
            default:
                break;
        }
        throw new UnsupportedOperationException();
    }
    
    /**
     * BASE64URL バイナリをBigIntegerにするだけ.
     * 
     * @param s BASE64URLエンコードな数値
     * @return new BigInteger(0x00 + BASE64URLdecode(s))
     */
    private static BigInteger decodeBigHex(String s) {
        BASE64 b64 = new BASE64(BASE64.URL,0);
        byte[] d = b64.decode(s);
        byte[] p = new byte[d.length + 1]; // フラグ消し
        System.arraycopy(d, 0, p, 1, d.length);
        return new BigInteger(p);
    }

    /**
     * 
     * @param alg
     * @param key
     * @return 
     */
    static HMAC toHMAC(String alg, byte[] key) {
        HMAC hmac = new HMAC(toDigest(alg));
        hmac.init(key);
        return hmac;
    }

    /**
     * 秘密鍵(最小)
     * @param jwk nとd
     * @return 秘密鍵 
     */
    static RSAMiniPrivateKey jwkToRSAPrivate(JSONObject jwk) {
        BigInteger n = decodeBigHex((String)jwk.get("n"));
        BigInteger d = decodeBigHex((String)jwk.get("d"));
        return new RSAMiniPrivateKey(n, d);
    }

    /**
     * 公開鍵
     * @param jwk nとe
     * @return 公開鍵
     */
    static RSAPublicKey jwkToRSAPublic(JSONObject jwk) {
        BigInteger n = decodeBigHex((String)jwk.get("n"));
        BigInteger e = decodeBigHex((String)jwk.get("e"));
        return new RSAPublicKey(n, e);
    }
    
    /**
     * RSASSAの選択.
     * @param alg アルゴリズム
     * @return RSASSA
     */
    static RSASSA toRSASSA(String alg) {
        if ( alg.startsWith("RS")) {
            return new PKCS1(alg);
        } else if ( alg.startsWith("PS")) {
            return new PSS(alg);
        }
        throw new UnsupportedOperationException();
    }

    /**
     * RSASSAの使いやすそうな形.
     */
    static abstract class RSASSA implements SignAlgorithm {

        net.siisise.security.sign.RSASSA ssa;
        
        /**
         * RSA秘密鍵で初期化.
         * @param jwkPrv JWK秘密鍵
         */
        @Override
        public void initPrivate(JSONObject jwkPrv) {
            ssa.init(jwkToRSAPrivate(jwkPrv));
        }

        /**
         * RSA公開鍵で初期化.
         * miniではない秘密鍵でも可
         * @param jwkPub JWK公開鍵
         */
        @Override
        public void initPublic(JSONObject jwkPub) {
            ssa.init(jwkToRSAPublic(jwkPub));
        }
        
        @Override
        public void update(byte[] m) {
            ssa.update(m);
        }
        
        @Override
        public byte[] sign() {
            return ssa.sign();
        }

        /**
         * JWK RSA秘密鍵で署名.
         * @param jwkPrv JWK RSA秘密鍵
         * @param data メッセージ
         * @return 署名
         */
        @Override
        public byte[] sign(JSONObject jwkPrv, byte[] data) {
            initPrivate(jwkPrv);
            update(data);
            return sign();
        }

        /**
         * 署名検証.
         * @param sign 署名
         * @return 可否
         */
        @Override
        public boolean verify(byte[] sign) {
            return ssa.verify(sign);
        }

        /**
         * 署名検証.
         * @param jwkPub JWK公開鍵 または JWKフル秘密鍵
         * @param data メッセージ
         * @param sign 署名
         * @return 可否
         */
        @Override
        public boolean verify(JSONObject jwkPub, byte[] data, byte[] sign) {
            initPublic(jwkPub);
            update(data);
            return verify(sign);
        }

    }

    /**
     * RSASSA-PKCS1-v1.5
     */
    static class PKCS1 extends RSASSA {
        
        PKCS1(String alg) {
            ssa = new RSASSA_PKCS1_v1_5(toDigest(alg));
        }
    }

    /**
     * RSASSA-PSS
     * SHAKE 以外
     */
    static class PSS extends RSASSA {

        PSS(String alg) {
            MessageDigest md = toDigest(alg);
            int dl = md.getDigestLength();
            MGF mgf = new MGF1(md);
            ssa = new RSASSA_PSS(toDigest(alg), mgf, dl);
        }
    }

    static StreamAEAD blockAlg(String alg) {
        if ("A128GCM".equals(alg)) {
            return new GCM(new AES(128));
        }
        if ("A192GCM".equals(alg)) {
            return new GCM(new AES(192));
        }
        if ("A256GCM".equals(alg)) {
            return new GCM(new AES(256));
        }
        if ("A128CBC-HS256".equals(alg)) {
            return new BlockAEAD(new AES(128), new HMAC(new SHA256()));
        }
        if ("A192CBC-HS384".equals(alg)) {
            return new BlockAEAD(new AES(192), new HMAC(new SHA384()));
        }
        if ("A256CBC-HS512".equals(alg)) {
            return new BlockAEAD(new AES(256), new HMAC(new SHA512()));
        }
        throw new UnsupportedOperationException();
    }
    
    static interface JWA_ES extends ES {
        void genHeader(JSONObject header);
        void readHeader(JSONObject header);
    }
    
    SecureRandom srnd;
    
    JWA7518() {
        try {
            srnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
        
    }

    /**
     * RFC 7518 section 4.1
     * KDF的な役割
     * 
     * @param alg
     * @return 
     */
    ES toES(JSONObject header) {
        String alg = header.getJSON("alg").map();
        // RSA
        if ( "RSA-OAEP".equals(alg)) { // RFC 3447 A.2.1 2048 bit 以上のRSA鍵
            return new RSAES_OAEP(); // SHA1
        } else if ( "RSA-OAEP-256".equals(alg)) { // RFC 3447 2048 bit 以上のRSA鍵
            return new RSAES_OAEP(new SHA256(), new SHA256());
        } else if ("RSA1_5".equals(alg)) { // RFC 3447 2048 bit 以上のRSA鍵
            return new RSAES_PKCS1_v1_5();

        // AES secret key
        } else if ("A128KW".equals(alg)) { // RFC 7518 4.4. RFC 3394
            return new ES_AKW(new AES(128));
        } else if ("A192KW".equals(alg)) { // RFC 3394
            return new ES_AKW(new AES(192));
        } else if ("A256KW".equals(alg)) { // RFC 3394
            return new ES_AKW(new AES(256));
        } else if ("A128GCMKW".equals(alg)) {
            return new ES_AGCMKW(new GCM(new AES(128)));
        } else if ("A192GCMKW".equals(alg)) {
            return new ES_AGCMKW(new GCM(new AES(192)));
        } else if ("A256GCMKW".equals(alg)) {
            return new ES_AGCMKW(new GCM(new AES(256)));

        // no key
        } else if ("dir".equals(alg)) {
            return new ES_DIR();

        // password
        } else if ("PBES2-HS256+A128KW".equals(alg)) {
            return new ES_PBES2(alg, new HMAC(new SHA256()), 128);
        } else if ("PBES2-HS384+A192KW".equals(alg)) {
            return new ES_PBES2(alg, new HMAC(new SHA384()), 192);
        } else if ("PBES2-HS512+A256KW".equals(alg)) {
            return new ES_PBES2(alg, new HMAC(new SHA512()), 256);
        }
        
        throw new UnsupportedOperationException(alg);
    }

    public static class AEADES extends RSAES {
        
        public AEADES(EME eme) {
            super(eme);
        }
        
        public void init(byte[] key, byte[] iv) {
            
        }
    }

    /**
     * 鍵保護なし
     */
    static class ES_DIR implements ES {

        @Override
        public byte[] encrypt(byte[] m) {
            return m;
        }

        @Override
        public byte[] decrypt(byte[] em) {
            return em;
        }
    }

    /**
     * AESKeyWrap
     */
    static class ES_AKW implements ES {
        AESKeyWrap kw;
        
        /**
         * 
         * @param aes AES
         * @param kek 鍵暗号化鍵
         */
        ES_AKW(AES aes) {
            kw = new AESKeyWrap(aes);
        }
        
        void init(byte[] kek) {
            kw.init(kek);
        }

        /**
         * 鍵を暗号化する.
         * @param m cek 鍵
         * @return encrypted_key
         */
        @Override
        public byte[] encrypt(byte[] m) {
            return kw.encrypt(m);
        }

        @Override
        public byte[] decrypt(byte[] em) {
            return kw.decrypt(em);
        }
    }

    /**
     * AES GCM Key wrapping
     */
    class ES_AGCMKW implements JWA_ES {
        StreamAEAD aead;
        byte[] kek;
        byte[] iv;
        byte[] tag;

        ES_AGCMKW(StreamAEAD aead) {
            this.aead = aead;
        }

        void init(byte[] kek) {
            this.kek = kek;
        }

        /**
         * 鍵を暗号化する.
         * @param m cek 鍵
         * @return encrypted_key
         */
        @Override
        public byte[] encrypt(byte[] m) {
            iv = new byte[12];
            srnd.nextBytes(iv);
            aead.init(kek,iv);
            byte[] enck = aead.encrypt(m);
            tag = aead.tag();
            return enck;
        }

        @Override
        public void genHeader(JSONObject header) {
            BASE64 url = new BASE64(BASE64.URL, 0);
            header.put("iv", url.encode(iv));
            header.put("tag", url.encode(tag));
        }

        @Override
        public void readHeader(JSONObject header) {
            BASE64 url = new BASE64(BASE64.URL, 0);
            iv = url.decode((String) header.get("iv")); // 96bit
            tag = url.decode((String) header.get("tag"));
        }

        @Override
        public byte[] decrypt(byte[] em) {
            aead.init(kek, iv);
            byte[] cek = aead.decrypt(em);
            byte[] t = aead.doFinalDecrypt(tag);
            if (t.length != 0) {
                throw new IllegalStateException();
            }
            return cek;
        }
    }

    /**
     * PBES2-HS256+A128KW.
     * PBES2-HS384+A192KW.
     * PBES2-HS512+A256KW.
     * PBKDF2 + AESKeyWrap しか使わない?
     */
    class ES_PBES2 implements JWA_ES {
        byte[] pass;
        int c = 2000;
        byte[] salt;
        String alg;
        PBKDF2 kdf;
        int dkLen;
        
        ES_PBES2(String alg, MAC mac, int len) {
            this.alg = alg;
            kdf = new PBKDF2(mac);
            dkLen = len;
        }

        void init(byte[] pass) {
            this.pass = pass;
        }

        /**
         * 
         * @param cek key
         * @return encrypted key
         */
        @Override
        public byte[] encrypt(byte[] cek) {
            PacketA s = new PacketA();
            salt = new byte[16]; // 8オクテット以上
            srnd.nextBytes(salt);
            c = 2000;
            s.write(alg.getBytes(StandardCharsets.UTF_8));
            s.write(0);
            s.write(salt);
            kdf.init(s.toByteArray(), c);
            
            byte[] k = kdf.kdf(pass, dkLen / 8);
            AESKeyWrap kw = new AESKeyWrap();
            kw.init(k);

            return kw.encrypt(cek);
        }

        @Override
        public void genHeader(JSONObject header) {
            BASE64 url = new BASE64(BASE64.URL, 0);
            header.put("p2s", url.encode(salt));
            header.put("p2c", c);
        }

        @Override
        public void readHeader(JSONObject header) {
            BASE64 url = new BASE64(BASE64.URL, 0);
            salt = url.decode((String) header.get("p2s"));
            c = (int) header.get("p2c");
        }

        /**
         * 
         * @param c encrypted_key
         * @return cek
         */
        @Override
        public byte[] decrypt(byte[] c) {
            PacketA s = new PacketA();
            s.write(alg.getBytes(StandardCharsets.UTF_8));
            s.write(0);
            s.write(salt);
            kdf.init(s.toByteArray(), this.c);
            
            byte[] k = kdf.kdf(pass, dkLen / 8);
            AESKeyWrap kw = new AESKeyWrap();
            kw.init(k);

            return kw.decrypt(c);
        }
    }
    
    /**
     * アルゴリズム
     * @param alg
     * @param key 鍵
     * @param iv 初期化ベクトル
     * @param aad null可
     * @return GCMなど(仮)
     */
    static StreamAEAD algo(String alg, byte[] key, byte[] iv, byte[] aad) {
        StreamAEAD aead = blockAlg(alg);
        if ( aad == null ) {
            aad = new byte[0];
        }
        aead.init(key, iv, aad);
        return aead;
    }
    
}
