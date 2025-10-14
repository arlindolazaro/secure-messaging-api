package com.securemessaging;

import com.securemessaging.service.CryptoService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class CryptoPGPRoundtripTest {

    private final CryptoService cryptoService = new CryptoService();

    @Test
    public void testPGPRoundtripWithArmor() throws Exception {
        KeyPair kp = cryptoService.generateRSAKeyPair(1024);
        String publicKey = cryptoService.keyToString(kp.getPublic());
        String privateKey = cryptoService.keyToString(kp.getPrivate());

        String message = "Mensagem de teste PGP roundtrip \uD83D\uDC4B";

        String encrypted = cryptoService.encryptPGPStyle(message, kp.getPublic());
        assertNotNull(encrypted);
        System.out.println("DEBUG encrypted (len=" + encrypted.length() + "): " + encrypted);
        System.out.println("DEBUG debugBase64: " + cryptoService.debugBase64(encrypted));

        // First verify raw decrypt works
        String decryptedRaw = cryptoService.decryptPGPStyle(encrypted, kp.getPrivate());
        assertEquals(message, decryptedRaw);

        // Simulate armored PGP by adding header/footer and a Version header
        String armored = "-----BEGIN PGP MESSAGE-----\nVersion: SecureMessagingTest\n\n" + encrypted
                + "\n-----END PGP MESSAGE-----";

        String decrypted = cryptoService.decryptPGPStyle(armored, kp.getPrivate());
        assertEquals(message, decrypted);
    }
}
