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
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
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
 *
 * Hardware keys (0.22): a token bound to a NIST P-256 public point (65 bytes {@code 0x04‖X‖Y}) gets the
 * {@link #SEALED_ALG_P256} envelope, which a TPM 2.0 (tpm2-pkcs11), an HSM or a smart card can open with one
 * ECDH derivation — they almost never speak X25519. Software P-256 keys come from {@link #generateP256KeyPair()}
 * (the private string is scalar‖point, 97 bytes). A key that lives in a PKCS#11 token is used through
 * {@link #withKeyProvider(PrivateKey, byte[])} with the {@code PrivateKey} obtained from a {@code SunPKCS11}
 * {@code KeyStore}; the key never leaves the device. Two SunPKCS11 facts worth knowing: the KeyStore shows a
 * private key only when a certificate with the same {@code CKA_ID} sits next to it (write one with
 * {@code pkcs11-tool --write-object … --type cert}), and the provider config needs
 * {@code attributes = compatibility} (or an explicit non-sensitive template for
 * {@code CKO_SECRET_KEY/CKK_GENERIC_SECRET}), otherwise the derived ECDH secret is created sensitive and
 * {@code generateSecret()} fails with {@code CKR_ATTRIBUTE_SENSITIVE}.
 *
 * Post-quantum hybrid (0.27): a token bound to a 1216-byte public key (X25519 pk ‖ ML-KEM-768 encapsulation key,
 * FIPS 203) gets the {@link #SEALED_ALG_PQC} envelope: the vault does an ephemeral X25519 exchange AND an ML-KEM-768
 * encapsulation, feeds both shared secrets into HKDF-SHA256 and seals with AES-256-GCM, so the value stays secret
 * unless both X25519 and ML-KEM fall. The private string is X25519 sk ‖ ML-KEM seed d‖z (96 bytes) from
 * {@link #generatePqcKeyPair()}; {@link #pqcPublicFromPrivate(String)} recomputes the public key from it (the ML-KEM
 * half with this client's own FIPS 203 KeyGen, see {@link MlKem}). Opening uses the JDK's {@code javax.crypto.KEM}
 * with "ML-KEM", which exists from <b>Java 24</b>; on older JDKs the client still compiles and runs, and the hybrid
 * envelope alone fails with "the post-quantum envelope needs Java 24+ (ML-KEM)". Everything else stays Java 11+.
 */
public final class VaultClient {

    public static final String VERSION = "0.31.1";
    public static final String SEALED_ALG = "X25519-HKDF-SHA256-AES256GCM";
    /** 0.19: GOST envelope — VKO GOST R 34.10-2012 (paramSetB) → KDF_TREE → Kuznyechik-MGM; see {@link Gost}. */
    public static final String SEALED_ALG_GOST = "VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM";
    /** 0.22: NIST P-256 envelope for hardware keys — ECDH(secp256r1) → HKDF-SHA256 → AES-256-GCM. */
    public static final String SEALED_ALG_P256 = "P256-HKDF-SHA256-AES256GCM";
    /** 0.27: post-quantum hybrid envelope — X25519 + ML-KEM-768 (FIPS 203) → HKDF-SHA256 → AES-256-GCM; needs Java 24+. */
    public static final String SEALED_ALG_PQC = "X25519MLKEM768-HKDF-SHA256-AES256GCM";
    private static final byte[] SEALED_INFO = "aps-vault/sealed/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SEALED_INFO_P256 = "aps-vault/sealed-p256/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SEALED_INFO_PQC = "aps-vault/sealed-pqc/v1".getBytes(StandardCharsets.UTF_8);
    private static final String DOES_NOT_OPEN = "sealed value does not open with this private key (wrong key, or the token is bound to another key)";
    private static final String P256_KEY_SHAPE = "P-256 private key must be scalar‖point (97 bytes) in this client — use generateP256KeyPair()";
    private static final String PQC_KEY_SHAPE = "hybrid private key must be 96 bytes: X25519 sk (32) ‖ ML-KEM-768 seed (64) — use generatePqcKeyPair()";
    /** Sizes of the hybrid key material: public = X25519 pk (32) ‖ ML-KEM ek (1184), private = X25519 sk (32) ‖ seed (64). */
    static final int PQC_PK_LEN = 32 + MlKem.EK_LEN, PQC_SK_LEN = 32 + MlKem.SEED_LEN;
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
    private final PrivateKey hwKey;      // 0.22: P-256 key living in a PKCS#11 token (null = software key or none)
    private final byte[] hwPoint;        // its 65-byte uncompressed public point
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
        this.hwKey = null;
        this.hwPoint = null;
    }

    private VaultClient(VaultClient o, PrivateKey hwKey, byte[] hwPoint) {
        this.base = o.base; this.token = o.token; this.clientKey = o.clientKey;
        this.cacheTtl = o.cacheTtl; this.timeout = o.timeout; this.maxRetries = o.maxRetries;
        this.failOpenCache = o.failOpenCache; this.http = o.http;
        this.hwKey = hwKey; this.hwPoint = hwPoint;
    }

    /** 0.22: a copy of this client that opens sealed values with a P-256 key held by a hardware token (TPM 2.0,
     *  HSM, smart card) through the JCA: {@code key} is the {@code PrivateKey} a {@code SunPKCS11} KeyStore returned,
     *  {@code publicPoint} its 65-byte uncompressed point ({@code 0x04‖X‖Y}, e.g. from the certificate next to it).
     *  ECDH runs inside the token ({@code KeyAgreement "ECDH"} picks the provider that owns the key); HKDF and AES-GCM
     *  run here. With a hardware key only the {@link #SEALED_ALG_P256} envelope opens — bind the token to this point. */
    public VaultClient withKeyProvider(PrivateKey key, byte[] publicPoint) {
        if (key == null) throw new IllegalArgumentException("vault: hardware private key required");
        if (!"EC".equals(key.getAlgorithm())) throw new IllegalArgumentException("vault: hardware key must be an EC (P-256) key, got " + key.getAlgorithm());
        checkPoint(publicPoint);
        return new VaultClient(this, key, publicPoint.clone());
    }

    private static void checkPoint(byte[] point) {
        if (point == null || point.length != 65 || point[0] != 4)
            throw new IllegalArgumentException("vault: P-256 public point must be 65 bytes uncompressed (0x04‖X‖Y)");
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

    /** {privateB64, publicB64} for the P-256 envelope (0.22). The private string is the 32-byte big-endian scalar
     *  followed by the 65-byte uncompressed public point (97 bytes) — self-contained, because the JDK cannot
     *  derive the point from a bare scalar; the public string is the 65-byte point to bind the token to. */
    public static String[] generateP256KeyPair() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        byte[] point = encodePoint(((ECPublicKey) kp.getPublic()).getW());
        byte[] scalar = fixed(((ECPrivateKey) kp.getPrivate()).getS(), 32);
        return new String[]{b64(concat(scalar, point)), b64(point)};
    }

    /** {privateB64, publicB64} for the post-quantum hybrid envelope (0.27): private = X25519 sk (32) ‖ ML-KEM-768
     *  seed d‖z (64) = 96 bytes, public = X25519 pk (32) ‖ ML-KEM-768 encapsulation key (1184) = 1216 bytes — the
     *  same layout every APS Vault client uses, so {@link #pqcPublicFromPrivate(String)} recovers the public half.
     *  The ML-KEM pair comes from the JDK ({@code KeyPairGenerator "ML-KEM-768"}, Java 24+); on an older JDK this
     *  throws {@code NoSuchAlgorithmException("the post-quantum envelope needs Java 24+ (ML-KEM)")}. */
    public static String[] generatePqcKeyPair() throws GeneralSecurityException {
        byte[][] kem = MlKem.generate();                                  // {seed, ek}; checks the JDK's seed-form encoding
        KeyPairGenerator g = KeyPairGenerator.getInstance("XDH");
        g.initialize(NamedParameterSpec.X25519);
        KeyPair x = g.generateKeyPair();
        byte[] xsk = x.getPrivate().getEncoded(), xpk = x.getPublic().getEncoded();
        xsk = Arrays.copyOfRange(xsk, xsk.length - 32, xsk.length); xpk = Arrays.copyOfRange(xpk, xpk.length - 32, xpk.length);
        return new String[]{b64(concat(xsk, kem[0])), b64(concat(xpk, kem[1]))};
    }

    /** The 1216-byte public key (base64) that belongs to a 96-byte hybrid private key: X25519 pk = sk · basepoint via
     *  the JDK, ML-KEM-768 encapsulation key = FIPS 203 KeyGen from the seed, computed by this client ({@link MlKem})
     *  because the JDK exposes no seed → public derivation. Works on any Java version. */
    public static String pqcPublicFromPrivate(String privateKeyB64) throws IOException {
        byte[] raw;
        try { raw = Base64.getDecoder().decode(privateKeyB64); }
        catch (IllegalArgumentException e) { throw new IOException("vault: hybrid key: " + e.getMessage(), e); }
        if (raw.length != PQC_SK_LEN) throw new VaultException(0, PQC_KEY_SHAPE + ", got " + raw.length + " bytes");
        try {
            KeyFactory kf = KeyFactory.getInstance("XDH");
            PrivateKey sk = kf.generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, Arrays.copyOf(raw, 32))));
            byte[] xpk = xdh(sk, kf.generatePublic(new X509EncodedKeySpec(concat(SPKI_PREFIX, X25519_BASEPOINT))));
            return b64(concat(xpk, MlKem.publicFromSeed(Arrays.copyOfRange(raw, 32, PQC_SK_LEN))));
        } catch (GeneralSecurityException e) {
            throw new IOException("vault: hybrid key: " + e.getMessage(), e);
        }
    }

    /** Open a sealed envelope (the flat pairs alg/v/epk/[ukm|kem]/nonce/ct of the machine-API response) with the
     *  private key; {@code name} is the secret's name (AAD). Returns the payload pairs. Dispatches on
     *  {@code alg}: X25519 ({@link #SEALED_ALG}, JDK XDH/AES-GCM), GOST ({@link #SEALED_ALG_GOST}, {@link Gost}),
     *  P-256 ({@link #SEALED_ALG_P256}, private key = scalar‖point from {@link #generateP256KeyPair()}) or the
     *  post-quantum hybrid ({@link #SEALED_ALG_PQC}, 96-byte key from {@link #generatePqcKeyPair()}, Java 24+). */
    public static Map<String, String> unseal(Map<String, String> env, String privateKeyB64, String name) throws IOException {
        if (SEALED_ALG_GOST.equals(env.get("alg")) && "1".equals(env.get("v")))
            return Gost.unsealGost(env, privateKeyB64, name);
        if (SEALED_ALG_P256.equals(env.get("alg")) && "1".equals(env.get("v")))
            return unsealP256(env, privateKeyB64, name);
        if (SEALED_ALG_PQC.equals(env.get("alg")) && "1".equals(env.get("v")))
            return unsealPqc(env, privateKeyB64, name);
        if (!SEALED_ALG.equals(env.get("alg")) || !"1".equals(env.get("v")))
            throw new VaultException(0, "unsupported sealed envelope " + env.get("alg") + " v" + env.get("v"));
        try {
            KeyFactory kf = KeyFactory.getInstance("XDH");
            byte[] skRaw = Base64.getDecoder().decode(privateKeyB64);
            if (skRaw.length != 32)     // older JDKs ignore bytes after the 32 the PKCS#8 declares — never let a longer key slip in
                throw new VaultException(0, "X25519 private key must be 32 bytes, got " + skRaw.length + " (this envelope is X25519; a GOST, P-256 or hybrid key does not open it)");
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

    // ── P-256 envelope (0.22) ───────────────────────────────────────────────
    /** Software path: the private key string is scalar‖point (97 bytes). */
    static Map<String, String> unsealP256(Map<String, String> env, String privateKeyB64, String name) throws IOException {
        byte[] raw;
        try { raw = Base64.getDecoder().decode(privateKeyB64); }
        catch (IllegalArgumentException e) { throw new IOException("vault: sealed envelope: " + e.getMessage(), e); }
        if (raw.length == 32) throw new VaultException(0, P256_KEY_SHAPE);
        if (raw.length != 97 || raw[32] != 4) throw new IOException("vault: sealed envelope: " + P256_KEY_SHAPE);
        byte[] point = Arrays.copyOfRange(raw, 32, 97);
        PrivateKey sk;
        try {
            BigInteger d = new BigInteger(1, Arrays.copyOf(raw, 32));
            sk = KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(d, p256()));
        } catch (GeneralSecurityException e) {
            throw new IOException("vault: sealed envelope: " + e.getMessage(), e);
        }
        return unsealP256(env, sk, point, name);
    }

    /** Core of the P-256 envelope, shared by the software key and a PKCS#11 key: ECDH with the ephemeral point,
     *  HKDF-SHA256(info = label ‖ epk ‖ our point), AES-256-GCM with the secret name as AAD. */
    static Map<String, String> unsealP256(Map<String, String> env, PrivateKey sk, byte[] ourPoint, String name) throws IOException {
        if (!SEALED_ALG_P256.equals(env.get("alg")) || !"1".equals(env.get("v")))
            throw new VaultException(0, "unsupported sealed envelope " + env.get("alg") + " v" + env.get("v"));
        byte[] epk, nonce, ct;
        try {
            epk = Base64.getDecoder().decode(req(env, "epk"));
            nonce = Base64.getDecoder().decode(req(env, "nonce"));
            ct = Base64.getDecoder().decode(req(env, "ct"));
            checkPoint(epk);
        } catch (IllegalArgumentException e) {
            throw new IOException("vault: sealed envelope: " + e.getMessage(), e);
        }
        byte[] shared;
        try {
            PublicKey peer = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(decodePoint(epk), p256()));
            shared = ecdh(sk, peer);
        } catch (InvalidKeyException e) {                 // the JDK refuses an off-curve / invalid ephemeral point
            throw new VaultException(0, DOES_NOT_OPEN);
        } catch (GeneralSecurityException | ProviderException e) {
            throw new IOException("vault: sealed envelope: P-256 key agreement failed: " + e, e);
        }
        try {
            byte[] key = hkdf(shared, concat(concat(SEALED_INFO_P256, epk), ourPoint), 32);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            c.updateAAD(name.getBytes(StandardCharsets.UTF_8));
            byte[] pt;
            try { pt = c.doFinal(ct); }
            catch (GeneralSecurityException e) { throw new VaultException(0, DOES_NOT_OPEN); }
            return parseFlat(new String(pt, StandardCharsets.UTF_8));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IOException("vault: sealed envelope: " + e.getMessage(), e);
        }
    }

    // ── post-quantum hybrid envelope (0.27) ─────────────────────────────────
    /** X25519 + ML-KEM-768: ss_x = XDH(sk_x, epk), ss_kem = ML-KEM.Decaps(seed, kem), key = HKDF-SHA256(ss_x ‖ ss_kem,
     *  info = label ‖ epk ‖ kem) — the info carries the ephemeral values only, not our public key — then AES-256-GCM
     *  with the secret name as AAD. The private string is X25519 sk ‖ ML-KEM seed (96 bytes). */
    static Map<String, String> unsealPqc(Map<String, String> env, String privateKeyB64, String name) throws IOException {
        if (!SEALED_ALG_PQC.equals(env.get("alg")) || !"1".equals(env.get("v")))
            throw new VaultException(0, "unsupported sealed envelope " + env.get("alg") + " v" + env.get("v"));
        byte[] raw;
        try { raw = Base64.getDecoder().decode(privateKeyB64); }
        catch (IllegalArgumentException e) { throw new IOException("vault: sealed envelope: " + e.getMessage(), e); }
        if (raw.length != PQC_SK_LEN) throw new VaultException(0, PQC_KEY_SHAPE + ", got " + raw.length + " bytes");
        byte[] epk, kem, nonce, ct;
        try {
            epk = Base64.getDecoder().decode(req(env, "epk"));
            kem = Base64.getDecoder().decode(req(env, "kem"));
            nonce = Base64.getDecoder().decode(req(env, "nonce"));
            ct = Base64.getDecoder().decode(req(env, "ct"));
        } catch (IllegalArgumentException e) {
            throw new IOException("vault: sealed envelope: " + e.getMessage(), e);
        }
        if (epk.length != 32 || kem.length != MlKem.CT_LEN)
            throw new IOException("vault: sealed envelope: hybrid envelope needs a 32-byte epk and a 1088-byte kem, got " + epk.length + " / " + kem.length);
        byte[] ssX, ssKem;
        try {
            KeyFactory kf = KeyFactory.getInstance("XDH");
            PrivateKey skX = kf.generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, Arrays.copyOf(raw, 32))));
            PrivateKey dk = MlKem.privateFromSeed(Arrays.copyOfRange(raw, 32, PQC_SK_LEN));   // NoSuchAlgorithmException → "needs Java 24+"
            try { ssX = xdh(skX, kf.generatePublic(new X509EncodedKeySpec(concat(SPKI_PREFIX, epk)))); }
            catch (InvalidKeyException e) { throw new VaultException(0, DOES_NOT_OPEN); }             // small-order ephemeral point
            ssKem = MlKem.decapsulate(dk, kem);                            // a damaged kem gives a different secret, not an error
        } catch (GeneralSecurityException | ProviderException e) {
            throw new IOException("vault: sealed envelope: " + e.getMessage(), e);
        }
        try {
            byte[] key = hkdf(concat(ssX, ssKem), concat(concat(SEALED_INFO_PQC, epk), kem), 32);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            c.updateAAD(name.getBytes(StandardCharsets.UTF_8));
            byte[] pt;
            try { pt = c.doFinal(ct); }
            catch (GeneralSecurityException e) { throw new VaultException(0, DOES_NOT_OPEN); }
            return parseFlat(new String(pt, StandardCharsets.UTF_8));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IOException("vault: sealed envelope: " + e.getMessage(), e);
        }
    }

    /** ECDH with whichever provider owns the key: the JCA tries every "ECDH" provider on {@code init} (SunEC for
     *  software keys, SunPKCS11 for P11Key handles); if that still fails, the SunPKCS11 providers are tried by name. */
    private static byte[] ecdh(PrivateKey sk, PublicKey peer) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        try {
            ka.init(sk);
        } catch (InvalidKeyException first) {
            ka = null;
            for (Provider p : Security.getProviders()) {
                if (!p.getName().startsWith("SunPKCS11")) continue;
                try { KeyAgreement k = KeyAgreement.getInstance("ECDH", p); k.init(sk); ka = k; break; }
                catch (GeneralSecurityException e) { first.addSuppressed(e); }
            }
            if (ka == null) throw first;
        }
        ka.doPhase(peer, true);
        return ka.generateSecret();
    }

    private static ECParameterSpec p256() throws GeneralSecurityException {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        return ap.getParameterSpec(ECParameterSpec.class);
    }

    /** 65-byte uncompressed point {@code 0x04‖X‖Y}. */
    static byte[] encodePoint(ECPoint w) { return concat(new byte[]{4}, concat(fixed(w.getAffineX(), 32), fixed(w.getAffineY(), 32))); }

    static ECPoint decodePoint(byte[] p) {
        checkPoint(p);
        return new ECPoint(new BigInteger(1, Arrays.copyOfRange(p, 1, 33)), new BigInteger(1, Arrays.copyOfRange(p, 33, 65)));
    }

    private static byte[] fixed(BigInteger v, int n) {
        byte[] b = v.toByteArray();
        if (b.length == n) return b;
        if (b.length > n) return Arrays.copyOfRange(b, b.length - n, b.length);   // strip the sign byte
        byte[] r = new byte[n]; System.arraycopy(b, 0, r, n - b.length, b.length); return r;
    }

    private static String req(Map<String, String> env, String k) {
        String v = env.get(k);
        if (v == null) throw new IllegalArgumentException("envelope field '" + k + "' missing");
        return v;
    }

    /** RFC 5869 HKDF-SHA256 with an all-zero salt (what the vault uses). */
    static byte[] hkdf(byte[] ikm, byte[] info, int n) throws GeneralSecurityException {
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

    /** Node enrolment (0.21): make this machine's key pair (X25519, or GOST when {@code gost}), redeem the one-time
     *  code and receive a token sealed to the new key. Returns {token, privateKey, publicKey, tokenName, folderName}.
     *  Keep token and privateKey with mode 0600 (VAULT_TOKEN / VAULT_CLIENT_KEY); the token alone opens nothing. */
    public static String[] enroll(String baseUrl, String code, String name, boolean gost) throws IOException, InterruptedException {
        return enroll(baseUrl, code, name, gost ? "gost" : "x25519");
    }

    /** Same with the key kind spelled out: {@code "x25519"}, {@code "gost"}, {@code "p256"} (0.22; the private
     *  string is then scalar‖point, see {@link #generateP256KeyPair()}) or {@code "pqc"} (0.27; X25519 + ML-KEM-768,
     *  96-byte private string, Java 24+ — see {@link #generatePqcKeyPair()}). */
    public static String[] enroll(String baseUrl, String code, String name, String kind) throws IOException, InterruptedException {
        String[] pair;
        try {
            switch (kind == null ? "x25519" : kind) {
                case "x25519": pair = generateKeyPair(); break;
                case "gost": pair = generateGostKeyPair(); break;
                case "p256": pair = generateP256KeyPair(); break;
                case "pqc": pair = generatePqcKeyPair(); break;
                default: throw new IllegalArgumentException("vault enrol: key kind must be x25519, gost, p256 or pqc, got " + kind);
            }
        } catch (GeneralSecurityException e) { throw new IOException("vault enrol: key generation failed: " + e.getMessage(), e); }
        Map<String, String> m = enrollPublic(baseUrl, code, name, pair[1]);
        return new String[]{m.get("raw_token"), pair[0], pair[1], m.get("token_name"), m.get("folder_name")};
    }

    /** 0.22: enrol with a P-256 key that lives in a hardware token — {@code hardwareKey} is the PKCS#11 private key
     *  handle (never leaves the device), {@code publicPoint} its 65-byte uncompressed point. Returns
     *  {token, "", publicB64, tokenName, folderName}: there is no private string to store, only the token; afterwards
     *  use {@link #withKeyProvider(PrivateKey, byte[])} with the same key. */
    public static String[] enroll(String baseUrl, String code, String name, PrivateKey hardwareKey, byte[] publicPoint) throws IOException, InterruptedException {
        if (hardwareKey == null) throw new IllegalArgumentException("vault enrol: hardware private key required");
        if (!"EC".equals(hardwareKey.getAlgorithm())) throw new IllegalArgumentException("vault enrol: hardware key must be an EC (P-256) key, got " + hardwareKey.getAlgorithm());
        checkPoint(publicPoint);
        String pub = b64(publicPoint);
        Map<String, String> m = enrollPublic(baseUrl, code, name, pub);
        return new String[]{m.get("raw_token"), "", pub, m.get("token_name"), m.get("folder_name")};
    }

    private static Map<String, String> enrollPublic(String baseUrl, String code, String name, String publicB64) throws IOException, InterruptedException {
        if (name == null || name.isEmpty()) name = java.net.InetAddress.getLocalHost().getHostName();
        String json = "{\"code\":" + q(code) + ",\"public_key\":" + q(publicB64) + ",\"name\":" + q(name.length() > 64 ? name.substring(0, 64) : name) + "}";
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl.replaceAll("/+$", "") + "/api/enroll")).timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json").header("Accept", "application/json").header("User-Agent", "aps-vault-java/" + VERSION)
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8)).build();
        HttpResponse<String> r = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build().send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Map<String, String> m = parseFlat(r.body());
        if (r.statusCode() / 100 != 2) throw new VaultException(r.statusCode(), "enrol: " + m.getOrDefault("detail", String.valueOf(r.statusCode())));
        return m;
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
            Map<String, String> payload;
            if (hwKey != null) {                                            // 0.22: the key sits in a PKCS#11 token
                if (!SEALED_ALG_P256.equals(flat.get("alg")))
                    throw new VaultException(0, "a hardware key opens only the P-256 envelope, the token sent " + flat.get("alg"));
                payload = unsealP256(flat, hwKey, hwPoint, flat.getOrDefault("name", name));
            } else {
                if (clientKey == null) throw new VaultException(0, "this token delivers sealed values — pass the client private key (or set VAULT_CLIENT_KEY)");
                payload = unseal(flat, clientKey, flat.getOrDefault("name", name));
            }
            flat.keySet().removeAll(Arrays.asList("alg", "v", "epk", "ukm", "kem", "nonce", "ct"));
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
    // The string parts are written as [^"\\]*(?:\\.[^"\\]*)* on purpose: java.util.regex recurses once per
    // iteration of an alternation group such as (?:[^"\\]|\\.)*, so a 1 500-character value (the ML-KEM
    // `kem` field, a hybrid public key) overflowed the stack on threads with a small stack (0.31.1). The
    // character-class loop is iterative; recursion now grows only with the number of escapes.
    private static final String STR = "[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*";
    private static final Pattern PAIR = Pattern.compile("\"(" + STR + ")\"\\s*:\\s*(\"" + STR + "\"|-?\\d+(?:\\.\\d+)?|true|false|null)");

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
