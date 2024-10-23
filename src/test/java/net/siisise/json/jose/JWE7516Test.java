/*
 * Copyright 2024 okome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.siisise.json.jose;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import net.siisise.json.JSONObject;
import net.siisise.security.key.RSAPrivateCrtKey;
import net.siisise.security.key.RSAPublicKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class JWE7516Test {
    
    public JWE7516Test() {
    }

    /**
     * Test of init method, of class JWE7516.
     * @throws java.security.NoSuchAlgorithmException RSA鍵生成
     */
    @Test
    public void testInit_RSAMiniPrivateKey() throws NoSuchAlgorithmException {
        System.out.println("init");
        RSAPrivateCrtKey key = net.siisise.security.key.RSAKeyGen.generatePrivateKey(2048);
        JWE7516 jwe = new JWE7516();
        jwe.init(key);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of init method, of class JWE7516.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testInit_RSAPublicKey() throws NoSuchAlgorithmException {
        System.out.println("init");
        RSAPrivateCrtKey key = net.siisise.security.key.RSAKeyGen.generatePrivateKey(2048);
        RSAPublicKey pub = key.getPublicKey();
        JWE7516 jwe = new JWE7516();
        jwe.init(pub);
    }

    /**
     * Test of compact method, of class JWE7516.
     */
    @Test
    public void testCompact() throws Exception {
        System.out.println("compact");
        byte[] payload = "The true sign of intelligence is not knowledge but imagination.".getBytes(StandardCharsets.UTF_8);
        JWE7516 jwe = new JWE7516();
        RSAPrivateCrtKey prvKey = net.siisise.security.key.RSAKeyGen.generatePrivateKey(2048);
        RSAPublicKey pubKey = prvKey.getPublicKey();
        jwe.init(pubKey);
        String expResult = "";
        String result = jwe.compact(payload);
        System.out.println(result);
        
        jwe = new JWE7516();
        jwe.init(prvKey);
        assertArrayEquals(payload, jwe.validateCompact(result));
    }

    /**
     * Test of json method, of class JWE7516.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testJson() throws NoSuchAlgorithmException {
        System.out.println("json");
        byte[] payload = "The true sign of intelligence is not knowledge but imagination.".getBytes(StandardCharsets.UTF_8);
        JWE7516 jwe = new JWE7516();
        RSAPrivateCrtKey prvKey = net.siisise.security.key.RSAKeyGen.generatePrivateKey(2048);
        RSAPublicKey pubKey = prvKey.getPublicKey();
        jwe.init(pubKey);
        JSONObject expResult = null;
        JSONObject result = jwe.json(payload);
        System.out.println(result.toJSON());

        jwe = new JWE7516();
        jwe.init(prvKey);
        assertArrayEquals(payload, jwe.validate(result));
    }
}
