package kh.eco.istad.authorizationserver.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PersistentRsaKeyStoreTest {
    @TempDir
    Path directory;

    @Test
    void signingKeyPersistsAcrossStoreInstancesAndPreviousPublicKeyRemainsTrustedForRotation() throws Exception {
        PersistentRsaKeyStore firstStore = new PersistentRsaKeyStore(directory);
        KeyPair firstKey = firstStore.loadOrCreate("default");
        String oldKeyId = PersistentRsaKeyStore.keyId(firstKey.getPublic());

        PersistentRsaKeyStore restartedStore = new PersistentRsaKeyStore(directory);
        KeyPair loadedKey = restartedStore.loadOrCreate("default");
        assertThat(loadedKey.getPublic().getEncoded()).isEqualTo(firstKey.getPublic().getEncoded());

        Path tenantDirectory = directory.resolve("default");
        Files.move(tenantDirectory.resolve("active-public.pem"),
                tenantDirectory.resolve("previous-" + oldKeyId + ".pem"));
        Files.delete(tenantDirectory.resolve("active-private.pem"));
        KeyPair rotatedKey = restartedStore.loadOrCreate("default");

        assertThat(rotatedKey.getPublic().getEncoded()).isNotEqualTo(firstKey.getPublic().getEncoded());
        RSAPublicKey retainedKey = restartedStore.publicKey("default", oldKeyId, rotatedKey);
        assertThat(retainedKey.getEncoded()).isEqualTo(firstKey.getPublic().getEncoded());
        if (Files.getFileStore(tenantDirectory).supportsFileAttributeView("posix")) {
            assertThat(Files.getPosixFilePermissions(tenantDirectory.resolve("active-private.pem")))
                    .containsExactlyInAnyOrder(
                            java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                            java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
        }
    }
}
