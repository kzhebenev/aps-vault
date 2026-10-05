import io.apsvault.VaultClient;

import java.io.IOException;

/**
 * javac -d /tmp/out ../../clients/java/src/main/java/io/apsvault/VaultClient.java App.java
 * VAULT_URL=https://vault.example.com VAULT_TOKEN=vlt_… java -cp /tmp/out App
 */
public final class App {
    public static void main(String[] args) throws Exception {
        VaultClient vault = VaultClient.fromEnv();
        try {
            VaultClient.Secret db = vault.getFull("db-password");
            String smtp = vault.get("smtp-password");
            System.out.printf("connecting as %s; smtp password length %d%n", db.login, smtp.length());
        } catch (VaultClient.VaultException e) {
            System.err.println("vault refused: HTTP " + e.status + " — " + e.getMessage()); // 404 not in folder, 401 revoked
            System.exit(1);
        } catch (IOException e) {
            System.err.println("vault unreachable: " + e.getMessage());
            System.exit(1);
        }
    }
}
