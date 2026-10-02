package io.apsvault;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Client for the APS Vault machine API (service tokens). Java 11+, no dependencies.
 *
 * <pre>
 *   VaultClient v = new VaultClient("https://vault.example.com", System.getenv("VAULT_TOKEN"));
 *   String dbPassword = v.get("db-password");
 *   VaultClient.Secret smtp = v.getFull("smtp");   // value, login, notes, totp (per token grants)
 *   v.put("db-password", "new-value", "app", "", "");  // token needs can_write
 * </pre>
 *
 * Values are cached for {@code cacheTtl} (default 5 minutes). When the vault is unreachable
 * a stale cached value is returned ({@code failOpenCache}), so a vault restart does not take
 * the application down; the first fetch still fails loudly. 429/5xx/network errors are retried
 * with 1 s, 2 s, 4 s back-off. Nothing is logged; {@link VaultException} carries the HTTP
 * status and the server's {@code detail}.
 *
 * The JSON handling here is deliberately minimal (flat objects with string/number/bool/null
 * values) so that the client has no dependency; responses of the machine API are exactly that.
 */
public final class VaultClient {

    public static final String VERSION = "0.7.0";

    /** One secret as returned by the machine API. Absent fields are {@code null}. */
    public static final class Secret {
        public final String name, value, login, notes, totp, updatedAt;
        Secret(Map<String, String> m) {
            name = m.get("name"); value = m.get("value"); login = m.get("login");
            notes = m.get("notes"); totp = m.get("totp"); updatedAt = m.get("updated_at");
        }
    }

    /** HTTP-level error from the vault. */
    public static final class VaultException extends IOException {
        public final int status;
        public VaultException(int status, String detail) { super("vault: HTTP " + status + " " + detail); this.status = status; }
    }

    private final String base, token;
    private final Duration cacheTtl;
    private final int maxRetries;
    private final boolean failOpenCache;
    private final HttpClient http;
    private final Duration timeout;
    private final ConcurrentHashMap<String, Object[]> cache = new ConcurrentHashMap<>(); // name → {Secret, expiresAtMillis}

    public VaultClient(String baseUrl, String token) {
        this(baseUrl, token, Duration.ofMinutes(5), Duration.ofSeconds(5), 3, true);
    }

    public VaultClient(String baseUrl, String token, Duration cacheTtl, Duration timeout, int maxRetries, boolean failOpenCache) {
        if (baseUrl == null || baseUrl.isEmpty()) throw new IllegalArgumentException("vault: base URL required");
        if (token == null || !token.startsWith("vlt_")) throw new IllegalArgumentException("vault: a service token (vlt_…) is required, not a master password");
        this.base = baseUrl.replaceAll("/+$", "");
        this.token = token;
        this.cacheTtl = cacheTtl;
        this.timeout = timeout;
        this.maxRetries = maxRetries;
        this.failOpenCache = failOpenCache;
        this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
    }

    /** VAULT_URL + VAULT_TOKEN, or VAULT_TOKEN_FILE pointing at a 0600 file. */
    public static VaultClient fromEnv() throws IOException {
        String tok = System.getenv("VAULT_TOKEN");
        if ((tok == null || tok.isEmpty()) && System.getenv("VAULT_TOKEN_FILE") != null) {
            tok = Files.readString(Path.of(System.getenv("VAULT_TOKEN_FILE"))).trim();
        }
        return new VaultClient(System.getenv("VAULT_URL"), tok);
    }

    public String get(String name) throws IOException, InterruptedException { return getFull(name).value; }

    public Secret getFull(String name) throws IOException, InterruptedException {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("vault: name required");
        Object[] hit = cache.get(name);
        long now = System.currentTimeMillis();
        if (hit != null && (long) hit[1] > now) return (Secret) hit[0];
        String body;
        try {
            body = request("GET", "/api/v1/m/secret/" + enc(name), null);
        } catch (IOException e) {
            boolean transientErr = !(e instanceof VaultException) || ((VaultException) e).status == 429 || ((VaultException) e).status >= 500;
            if (hit != null && failOpenCache && transientErr) return (Secret) hit[0];
            throw e;
        }
        Secret s = new Secret(parseFlat(body));
        if (!cacheTtl.isZero() && !cacheTtl.isNegative()) cache.put(name, new Object[]{s, now + cacheTtl.toMillis()});
        return s;
    }

    /** Create or update a secret in the token's folder (token must have can_write). */
    public void put(String name, String value, String login, String tags, String url) throws IOException, InterruptedException {
        String json = "{\"value\":" + q(value) + ",\"login\":" + q(login) + ",\"tags\":" + q(tags) + ",\"url\":" + q(url) + "}";
        request("POST", "/api/v1/m/secret/" + enc(name), json);
        cache.remove(name);
    }

    /** Current TOTP code (token must have can_read_totp); empty if the secret has no seed. */
    public Optional<String> totp(String name) throws IOException, InterruptedException {
        cache.remove(name);
        return Optional.ofNullable(parseFlat(request("GET", "/api/v1/m/secret/" + enc(name), null)).get("totp"));
    }

    /** Raw JSON of GET /api/v1/m/health — token name, scope folder, grants. */
    public String health() throws IOException, InterruptedException { return request("GET", "/api/v1/m/health", null); }

    /** Raw JSON array of secrets in scope (no values). */
    public String list() throws IOException, InterruptedException { return request("GET", "/api/v1/m/secrets", null); }

    public void clearCache() { cache.clear(); }

    // ── transport ───────────────────────────────────────────────────────────
    private String request(String method, String path, String json) throws IOException, InterruptedException {
        IOException last = null;
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).timeout(timeout)
                    .header("Authorization", "Bearer " + token).header("Accept", "application/json")
                    .header("Content-Type", "application/json").header("User-Agent", "aps-vault-java/" + VERSION);
            b = json == null ? b.method(method, HttpRequest.BodyPublishers.noBody())
                             : b.method(method, HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));
            try {
                HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                int st = r.statusCode();
                if (st / 100 == 2) return r.body();
                String detail = parseFlat(r.body()).getOrDefault("detail", String.valueOf(st));
                last = new VaultException(st, detail);
                if (!(st == 429 || st >= 500)) throw last;
            } catch (VaultException e) {
                throw e;
            } catch (IOException e) {
                last = e;
            }
            if (attempt < maxRetries) Thread.sleep(1000L << attempt);
        }
        throw new IOException("vault: request failed after " + (maxRetries + 1) + " attempts", last);
    }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20"); }

    private static String q(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: if (c < 0x20) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    // "key": "string" | number | true | false | null — the machine API never nests values.
    private static final Pattern PAIR = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|-?\\d+(?:\\.\\d+)?|true|false|null)");

    static Map<String, String> parseFlat(String json) {
        Map<String, String> out = new java.util.HashMap<>();
        if (json == null) return out;
        Matcher m = PAIR.matcher(json);
        while (m.find()) {
            String k = unescape(m.group(1));
            String v = m.group(2);
            if ("null".equals(v)) out.put(k, null);
            else if (v.startsWith("\"")) out.put(k, unescape(v.substring(1, v.length() - 1)));
            else out.put(k, v);
        }
        return out;
    }

    private static String unescape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) { sb.append(c); continue; }
            char n = s.charAt(++i);
            switch (n) {
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case 'u': sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16)); i += 4; break;
                default: sb.append(n);
            }
        }
        return sb.toString();
    }
}
