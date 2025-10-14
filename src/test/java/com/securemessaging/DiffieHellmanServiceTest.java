package com.securemessaging;

import com.securemessaging.service.CryptoService;
import com.securemessaging.service.DiffieHellmanService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class DiffieHellmanServiceTest {

    private final CryptoService cryptoService = new CryptoService();
    private final DiffieHellmanService dhService = new DiffieHellmanService(cryptoService);

    @Test
    public void testDHAgreementCreatesSameAESKey() throws Exception {
        Map<String, Object> alice = dhService.initializeDiffieHellman();
        Map<String, Object> bob = dhService.initializeDiffieHellman();

        String alicePub = (String) alice.get("publicKey");
        String bobPub = (String) bob.get("publicKey");

        Map<String, Object> aliceShared = dhService.calculateSharedSecret((String) alice.get("sessionId"), bobPub);
        Map<String, Object> bobShared = dhService.calculateSharedSecret((String) bob.get("sessionId"), alicePub);

        assertEquals(aliceShared.get("sharedSecret"), bobShared.get("sharedSecret"));

        SecretKey keyA = dhService.getAESKeyForSession((String) alice.get("sessionId"));
        SecretKey keyB = dhService.getAESKeyForSession((String) bob.get("sessionId"));

        assertNotNull(keyA);
        assertNotNull(keyB);
        assertEquals(16, keyA.getEncoded().length);
        assertEquals(16, keyB.getEncoded().length);
    }
}
