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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
 *
 * Sealed delivery (0.17): a token bound to this application's X25519 public key gets values
 * encrypted to that key; pass the private key (base64 raw 32 bytes) to the constructor or set
 * {@code VAULT_CLIENT_KEY}, and the client decrypts in-process with the JDK's XDH / AES-GCM.
 * {@link #generateKeyPair()} makes the pair. A token bound to a GOST R 34.10-2012 public key
 * (64 bytes X‖Y, from {@link #generateGostKeyPair()}) gets the GOST envelope instead
 * ({@link #SEALED_ALG_GOST}); the client picks the algorithm from the envelope's {@code alg}.
 */
public final class VaultClient {

    public static final String VERSION = "0.19.0";
    public static final String SEALED_ALG = "X25519-HKDF-SHA256-AES256GCM";
    /** 0.19: GOST envelope — VKO GOST R 34.10-2012 (paramSetB) → KDF_TREE → Kuznyechik-MGM; see {@link Gost}. */
    public static final String SEALED_ALG_GOST = "VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM";
    private static final byte[] SEALED_INFO = "aps-vault/sealed/v1".getBytes(StandardCharsets.UTF_8);
    // DER prefixes turning a raw 32-byte X25519 key into SPKI / PKCS#8 for the JDK
    private static final byte[] SPKI_PREFIX = hex("302a300506032b656e032100");
    private static final byte[] PKCS8_PREFIX = hex("302e020100300506032b656e04220420");
    private static final byte[] X25519_BASEPOINT = {9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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

    private final String base, token, clientKey;
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
        this(baseUrl, token, cacheTtl, timeout, maxRetries, failOpenCache, System.getenv("VAULT_CLIENT_KEY"));
    }

    /** {@code clientPrivateKey}: base64 raw X25519 private key for sealed tokens (null = none). */
    public VaultClient(String baseUrl, String token, Duration cacheTtl, Duration timeout, int maxRetries, boolean failOpenCache, String clientPrivateKey) {
        if (baseUrl == null || baseUrl.isEmpty()) throw new IllegalArgumentException("vault: base URL required");
        if (token == null || !token.startsWith("vlt_")) throw new IllegalArgumentException("vault: a service token (vlt_…) is required, not a master password");
        this.base = baseUrl.replaceAll("/+$", "");
        this.token = token;
        this.cacheTtl = cacheTtl;
        this.timeout = timeout;
        this.maxRetries = maxRetries;
        this.failOpenCache = failOpenCache;
        this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
        this.clientKey = (clientPrivateKey == null || clientPrivateKey.isEmpty()) ? null : clientPrivateKey;
    }

    // ── sealed delivery ─────────────────────────────────────────────────────
    /** {privateB64, publicB64}: raw 32-byte X25519 keys in standard base64. Give the public half to the
     *  vault administrator (token field client_public_key); keep the private half with the token. */
    public static String[] generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("XDH");
        g.initialize(NamedParameterSpec.X25519);
        KeyPair kp = g.generateKeyPair();
        byte[] sk = kp.getPrivate().getEncoded(), pk = kp.getPublic().getEncoded();
        return new String[]{b64(Arrays.copyOfRange(sk, sk.length - 32, sk.length)), b64(Arrays.copyOfRange(pk, pk.length - 32, pk.length))};
    }

    /** {privateB64, publicB64} for the GOST envelope: 32-byte big-endian scalar (GOST R 34.10-2012, curve
     *  paramSetB) and the 64-byte X‖Y little-endian public point. Same handling as {@link #generateKeyPair()}. */
    public static String[] generateGostKeyPair() { return Gost.generateGostKeyPair(); }

    /** Open a sealed envelope (the flat pairs alg/v/epk/[ukm]/nonce/ct of the machine-API response) with the
     *  private key; {@code name} is the secret's name (AAD). Returns the payload pairs. Dispatches on
     *  {@code alg}: X25519 ({@link #SEALED_ALG}, JDK XDH/AES-GCM) or GOST ({@link #SEALED_ALG_GOST}, {@link Gost}). */
    public static Map<String, String> unseal(Map<String, String> env, String privateKeyB64, String name) throws IOException {
        if (SEALED_ALG_GOST.equals(env.get("alg")) && "1".equals(env.get("v")))
            return Gost.unsealGost(env, privateKeyB64, name);
        if (!SEALED_ALG.equals(env.get("alg")) || !"1".equals(env.get("v")))
            throw new VaultException(0, "unsupported sealed envelope " + env.get("alg") + " v" + env.get("v"));
        try {
            KeyFactory kf = KeyFactory.getInstance("XDH");
            byte[] skRaw = Base64.getDecoder().decode(privateKeyB64);
            PrivateKey sk = kf.generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, skRaw)));
            byte[] epk = Base64.getDecoder().decode(env.get("epk"));
            byte[] pk = xdh(sk, kf.generatePublic(new X509EncodedKeySpec(concat(SPKI_PREFIX, X25519_BASEPOINT))));   // our public key = sk · basepoint
            byte[] shared = xdh(sk, kf.generatePublic(new X509EncodedKeySpec(concat(SPKI_PREFIX, epk))));
            byte[] key = hkdf(shared, concat(concat(SEALED_INFO, epk), pk), 32);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, Base64.getDecoder().decode(env.get("nonce"))));
            c.updateAAD(name.getBytes(StandardCharsets.UTF_8));
            byte[] pt;
            try { pt = c.doFinal(Base64.getDecoder().decode(env.get("ct"))); }
            catch (GeneralSecurityException e) { throw new VaultException(0, "sealed value does not open with this private key (wrong key, or the token is bound to another key)"); }
            return parseFlat(new String(pt, StandardCharsets.UTF_8));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IOException("vault: sealed envelope: " + e.getMessage(), e);
        }
    }

    private static byte[] xdh(PrivateKey sk, PublicKey pk) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(sk); ka.doPhase(pk, true);
        return ka.generateSecret();
    }

    /** RFC 5869 HKDF-SHA256 with an all-zero salt (what the vault uses). */
    private static byte[] hkdf(byte[] ikm, byte[] info, int n) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        byte[] out = new byte[0], prev = new byte[0];
        for (byte i = 1; out.length < n; i++) {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(prev); mac.update(info); mac.update(i);
            prev = mac.doFinal();
            out = concat(out, prev);
        }
        return Arrays.copyOf(out, n);
    }

    private static byte[] concat(byte[] a, byte[] b) { byte[] r = Arrays.copyOf(a, a.length + b.length); System.arraycopy(b, 0, r, a.length, b.length); return r; }
    private static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    private static byte[] hex(String h) { byte[] r = new byte[h.length() / 2]; for (int i = 0; i < r.length; i++) r[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16); return r; }

    /** VAULT_URL + VAULT_TOKEN, or VAULT_TOKEN_FILE pointing at a 0600 file. */
    public static VaultClient fromEnv() throws IOException {
        String tok = System.getenv("VAULT_TOKEN");
        if ((tok == null || tok.isEmpty()) && System.getenv("VAULT_TOKEN_FILE") != null) {
            tok = Files.readString(Path.of(System.getenv("VAULT_TOKEN_FILE"))).trim();
        }
        return new VaultClient(System.getenv("VAULT_URL"), tok);
    }

    public String get(String name) throws IOException, InterruptedException { return getFull(name).value; }

    /** An older value by version number — e.g. the previous encryption key during a rotation. */
    public String get(String name, int version) throws IOException, InterruptedException { return getFull(name, version).value; }

    public Secret getFull(String name) throws IOException, InterruptedException { return getFull(name, 0); }

    /** version 0 = current. */
    public Secret getFull(String name, int version) throws IOException, InterruptedException {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("vault: name required");
        String key = version > 0 ? name + "@" + version : name;
        Object[] hit = cache.get(key);
        long now = System.currentTimeMillis();
        if (hit != null && (long) hit[1] > now) return (Secret) hit[0];
        String body;
        try {
            body = request("GET", "/api/v1/m/secret/" + enc(name) + (version > 0 ? "?version=" + version : ""), null);
        } catch (IOException e) {
            boolean transientErr = !(e instanceof VaultException) || ((VaultException) e).status == 429 || ((VaultException) e).status >= 500;
            if (hit != null && failOpenCache && transientErr) return (Secret) hit[0];
            throw e;
        }
        Map<String, String> flat = parseFlat(body);
        if (flat.containsKey("ct") && flat.containsKey("epk")) {          // 0.17: sealed envelope instead of plaintext fields
            if (clientKey == null) throw new VaultException(0, "this token delivers sealed values — pass the client private key (or set VAULT_CLIENT_KEY)");
            Map<String, String> payload = unseal(flat, clientKey, flat.getOrDefault("name", name));
            flat.keySet().removeAll(Arrays.asList("alg", "v", "epk", "ukm", "nonce", "ct"));
            flat.putAll(payload);
        }
        Secret s = new Secret(flat);
        if (!cacheTtl.isZero() && !cacheTtl.isNegative()) cache.put(key, new Object[]{s, now + cacheTtl.toMillis()});
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
        Secret s = getFull(name);
        cache.remove(name);          // codes change every 30 s — never serve from cache
        return Optional.ofNullable(s.totp);
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
