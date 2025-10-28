package com.securemessaging.service;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class DiffieHellmanServiceTest {

    @Test
    public void testSimulateDHAgreement() throws Exception {
        CryptoService cryptoService = new CryptoService();
        DiffieHellmanService dhService = new DiffieHellmanService(cryptoService);

        Map<String, Object> result = dhService.simulateDHAgreement();

        assertNotNull(result);
        assertTrue((Boolean) result.get("success"));
        assertEquals(result.get("sharedSecretA"), result.get("sharedSecretB"));
        assertEquals(result.get("aesKeyA"), result.get("aesKeyB"));
        assertTrue((Boolean) result.get("keysMatch"));
    }
}
