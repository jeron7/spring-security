package dev.jeron7.springsecurityexamples.config;

import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import javax.naming.ConfigurationException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Component
public class LocalRSAKeyProvider implements RSAKeyProvider {

    private final PublicKey publicKey;

    private final PrivateKey privateKey;

    private LocalRSAKeyProvider() throws ConfigurationException {
        this.publicKey = loadPublicKey();
        this.privateKey = loadPrivateKey();
    }

    @Override
    public RSAPublicKey getPublicKeyById(String s) {
        return (RSAPublicKey) publicKey;
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return (RSAPrivateKey) privateKey;
    }

    @Override
    public String getPrivateKeyId() {
        return null;
    }

    private PublicKey loadPublicKey() throws ConfigurationException {
        try {
            var keyBytes = getKeyBytes("public.der");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            var keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ConfigurationException("Error while loading public key.");
        }
    }

    private PrivateKey loadPrivateKey() throws ConfigurationException {
        try {
            var keyBytes = getKeyBytes("private.der");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            var keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ConfigurationException("Error while loading private key.");
        }
    }

    protected byte[] getKeyBytes(String keyFileName) throws IOException {
        Resource keyFile = new ClassPathResource(STR."keys/\{keyFileName}");

        if (!keyFile.exists())
            throw new FileNotFoundException("You should add a public or private key at /keys dir.");

        return Files.readAllBytes(keyFile.getFile().toPath());
    }
}
