package com.securemessaging.config;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import java.security.KeyStore;

@Component
@Profile("dev")
public class DevKeystoreGenerator implements ApplicationRunner {

    private static final String KEYSTORE_PATH = "src/main/resources/keystore.p12";
    private static final String ALIAS = "securemessaging";
    private static final String PASSWORD = "changeit";

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Path ksPath = Path.of(KEYSTORE_PATH);
        if (Files.exists(ksPath)) {
            System.out.println("Dev keystore already exists: " + ksPath.toAbsolutePath());
            return;
        }

        System.out.println("Dev keystore not found. Generating: " + ksPath.toAbsolutePath());

        // Ensure parent dir exists
        File parent = ksPath.toFile().getParentFile();
        if (!parent.exists())
            parent.mkdirs();

        // Register BouncyCastle provider if missing
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Generate RSA keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // Build self-signed certificate
        X500Name subject = new X500Name("CN=SecureMessagingDev, OU=Dev, O=SecureMessaging, L=Local, ST=Local, C=US");
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(now.plus(3650, ChronoUnit.DAYS));
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                serial,
                notBefore,
                notAfter,
                subject,
                kp.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build((PrivateKey) kp.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certHolder);

        // Create PKCS12 keystore and save
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(ALIAS, kp.getPrivate(), PASSWORD.toCharArray(), new java.security.cert.Certificate[] { cert });

        try (FileOutputStream fos = new FileOutputStream(ksPath.toFile())) {
            ks.store(fos, PASSWORD.toCharArray());
        }

        System.out.println("Dev keystore generated at: " + ksPath.toAbsolutePath());
    }
}
