/*
 * Copyright 2023 okome.
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
import net.siisise.io.BASE64;
import net.siisise.json.JSON;
import net.siisise.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class JWS7515Test {
    
    public JWS7515Test() {
    }
    
    @BeforeAll
    public static void setUpClass() {
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    @BeforeEach
    public void setUp() {
    }
    
    @AfterEach
    public void tearDown() {
    }
    
    @Test
    public void testExample3() throws NoSuchAlgorithmException {
        System.out.println("RFC 7515 Section 3.3. Example JWS");
        JWS7515 jws = new JWS7515();
        JSONObject jwk = new JSONObject();
        String expResult = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                + ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
                + ".d6nMDXnJZfNNj-1o1e75s6d0six0lkLp5hSrGaz4o9A";
        jwk.put("kty", "oct");
        jwk.put("k", "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        BASE64 b64 = new BASE64(BASE64.URL, 0);
        byte[] hkey = b64.decode((String) jwk.get("k"));
        
        JSONObject payExample = new JSONObject();
        payExample.put("iss", "joe");
        payExample.put("exp", 1300819380);
        payExample.put("http://example.com/is_root", true);
        System.out.println(((String)payExample.rebind(JSON.NOBR_MINESC)));
        System.out.println(((String)payExample.toJSON()));
        
        byte[] payload = ((String)payExample.rebind(JSON.NOBR_MINESC)).getBytes(StandardCharsets.UTF_8);
        
        jws.setTyp("JWT");
        jws.setKey(hkey); // HMAC-SHA-256 前提
        String rsJWS = jws.compact(payExample.toJSON());
        
        byte[] valid = jws.validateCompact(rsJWS);
        
        assertArrayEquals(payload, valid);
        assertEquals(expResult, rsJWS);
    }

    /**
     * Test of compact method, of class JWS7515.
     */
    @Test
    public void testCompact_String() {
        System.out.println("compact");
        String payload = "";
        JWS7515 instance = new JWS7515();
        //instance.setsetAlg("RS256");
        String expResult = "";
        String result = instance.compact(payload);
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of compactHeader method, of class JWS7515.
     */
    @Test
    public void testCompactHeader() {
        System.out.println("compactHeader");
        JWS7515 instance = new JWS7515();
        String expResult = "";
        String result = instance.compactHeader();
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of json method, of class JWS7515.
     */
    @Test
    public void testJson() {
        System.out.println("json");
        byte[] payload = null;
        JWS7515 instance = new JWS7515();
        JSONObject expResult = null;
        JSONObject result = instance.json(payload);
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
}
