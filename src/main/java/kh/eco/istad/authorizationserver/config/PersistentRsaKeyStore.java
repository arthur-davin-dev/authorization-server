package kh.eco.istad.authorizationserver.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Loads persistent local RSA signing keys and retained public keys used during rotation. */
@Component
public final class PersistentRsaKeyStore {
    private final Path baseDirectory;

    public PersistentRsaKeyStore(@Value("${app.oauth.signing-key-dir:.local-keys}") Path baseDirectory) {
        this.baseDirectory = baseDirectory.toAbsolutePath().normalize();
    }

    public KeyPair loadOrCreate(String tenantId) throws Exception {
        Path directory = tenantDirectory(tenantId);
        Path privateFile = directory.resolve("active-private.pem");
        Path publicFile = directory.resolve("active-public.pem");
        Files.createDirectories(directory);
        setPermissions(directory, EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
        if (Files.isSymbolicLink(privateFile) || Files.isSymbolicLink(publicFile)) {
            throw new IllegalStateException("RSA key files must not be symbolic links for tenant " + tenantId);
        }
        boolean privateExists = Files.exists(privateFile);
        boolean publicExists = Files.exists(publicFile);
        if (privateExists != publicExists) {
            throw new IllegalStateException("Both active RSA key files must exist for tenant " + tenantId);
        }
        if (privateExists) {
            setPermissions(privateFile, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            RSAPublicKey publicKey = readPublicKey(publicFile);
            RSAPrivateKey privateKey = (RSAPrivateKey) readPrivateKey(privateFile);
            if (!publicKey.getModulus().equals(privateKey.getModulus())) {
                throw new IllegalStateException("Active RSA public and private keys do not match for tenant " + tenantId);
            }
            return new KeyPair(publicKey, privateKey);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair generated = generator.generateKeyPair();
        writePem(privateFile, "PRIVATE KEY", generated.getPrivate().getEncoded());
        writePem(publicFile, "PUBLIC KEY", generated.getPublic().getEncoded());
        return generated;
    }

    public List<RSAPublicKey> publicKeys(String tenantId, KeyPair activeKeyPair) throws Exception {
        List<RSAPublicKey> keys = new ArrayList<>();
        keys.add((RSAPublicKey) activeKeyPair.getPublic());
        Path directory = tenantDirectory(tenantId);
        try (Stream<Path> files = Files.list(directory)) {
            for (Path file : files.filter(path -> path.getFileName().toString().startsWith("previous-")
                    && path.getFileName().toString().endsWith(".pem")).toList()) {
                if (Files.isSymbolicLink(file)) {
                    throw new IllegalStateException("Retained RSA public keys must not be symbolic links");
                }
                keys.add(readPublicKey(file));
            }
        }
        return List.copyOf(keys);
    }

    public RSAPublicKey publicKey(String tenantId, String keyId, KeyPair activeKeyPair) throws Exception {
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalArgumentException("JWT is missing its key ID");
        }
        for (RSAPublicKey publicKey : publicKeys(tenantId, activeKeyPair)) {
            if (keyId(publicKey).equals(keyId)) {
                return publicKey;
            }
        }
        throw new IllegalArgumentException("JWT key ID is not trusted for this issuer");
    }

    public static String keyId(PublicKey publicKey) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
        return HexFormat.of().formatHex(digest, 0, 16);
    }

    private Path tenantDirectory(String tenantId) {
        return baseDirectory.resolve(tenantId);
    }

    private static RSAPublicKey readPublicKey(Path file) throws Exception {
        String pem = Files.readString(file);
        byte[] encoded = decodePem(pem, "PUBLIC KEY");
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
        return (RSAPublicKey) key;
    }

    private static PrivateKey readPrivateKey(Path file) throws Exception {
        String pem = Files.readString(file);
        byte[] encoded = decodePem(pem, "PRIVATE KEY");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    private static byte[] decodePem(String pem, String label) {
        String body = pem.replace("-----BEGIN " + label + "-----", "")
                .replace("-----END " + label + "-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    private static void writePem(Path target, String label, byte[] bytes) throws IOException {
        String encoded = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(bytes);
        Path temporary = Files.createTempFile(target.getParent(), target.getFileName().toString(), ".tmp");
        setPermissions(temporary,
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        Files.writeString(temporary, "-----BEGIN " + label + "-----\n" + encoded
                + "\n-----END " + label + "-----\n");
        try {
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException exception) {
            Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
        }
        setPermissions(target, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
    }

    private static void setPermissions(Path file, EnumSet<PosixFilePermission> permissions) {
        try {
            Files.setPosixFilePermissions(file, permissions);
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystems rely on their platform's user-only workspace permissions.
        } catch (IOException exception) {
            throw new IllegalStateException("Could not restrict signing key file permissions", exception);
        }
    }
}
