package io.apsvault;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dependency-free test (no JUnit so it runs with `java` alone):
 *   javac -d /tmp/out src/main/java/io/apsvault/*.java src/test/java/io/apsvault/*.java && java -cp /tmp/out io.apsvault.VaultClientTest
 * Exit code 0 = all assertions passed.
 */
public final class VaultClientTest {
    static final AtomicBoolean failing = new AtomicBoolean(false);
    static final AtomicInteger hits = new AtomicInteger();

    static void check(boolean cond, String msg) { if (!cond) throw new AssertionError(msg); }

    // ── GOST fixture helpers (clients/fixtures/gost-sealed.json, read relative to clients/java) ──
    static String fixtureJson;      // whole file; the nested objects flatten into top-level pairs
    static String gostSealedJson;   // the "sealed": {...} object of the envelope, as text

    /** The flat pairs of one top-level section: from its key to the next closing brace (or to the end for the nested envelope). */
    static Map<String, String> section(String key) {
        int i = fixtureJson.indexOf("\"" + key + "\"");
        check(i >= 0, "fixture section " + key);
        int j = key.equals("envelope") ? fixtureJson.length() : fixtureJson.indexOf("}", i) + 1;
        return VaultClient.parseFlat(fixtureJson.substring(i, j));
    }

    static byte[] hex(String h) {
        if (h.startsWith("0x")) h = h.substring(2);
        byte[] r = new byte[h.length() / 2];
        for (int i = 0; i < r.length; i++) r[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return r;
    }

    static String hex(byte[] b) { StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02x", x & 0xff)); return sb.toString(); }
    static byte[] b64(String s) { return Base64.getDecoder().decode(s); }
    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    /** Every entry of the fixture file, algorithm by algorithm (GOST-PORTING.md §6). */
    static void gostTests() throws Exception {
        // Streebog: M1/M2 both lengths, empty string
        Map<String, String> s = section("streebog");
        check(hex(Gost.streebog256(hex(s.get("M1")))).equals(s.get("M1_256")), "streebog256 M1");
        check(hex(Gost.streebog512(hex(s.get("M1")))).equals(s.get("M1_512")), "streebog512 M1");
        check(hex(Gost.streebog256(hex(s.get("M2")))).equals(s.get("M2_256")), "streebog256 M2");
        check(hex(Gost.streebog512(hex(s.get("M2")))).equals(s.get("M2_512")), "streebog512 M2");
        check(hex(Gost.streebog256(new byte[0])).equals(s.get("empty_256")), "streebog256 empty");
        // the 64-byte boundary (exactly one full block, then an all-padding block) must agree with gostcrypto
        // (values computed with backend/gost.py → gostcrypto)
        check(hex(Gost.streebog256(new byte[64])).equals("df1fda9ce83191390537358031db2ecaa6aa54cd0eda241dc107105e13636b95"), "streebog256 of 64 zero bytes");
        check(hex(Gost.streebog512(new byte[64])).equals("b0fd29ac1b0df441769ff3fdb8dc564df67721d6ac06fb28ceffb7bbaa7948c6c014ac999235b58cb26fb60fb112a145d7b4ade9ae566bf2611402c552d20db7"), "streebog512 of 64 zero bytes");

        // HMAC and KDF_TREE
        Map<String, String> h = section("hmac_streebog256");
        check(hex(Gost.hmacStreebog256(hex(h.get("key")), hex(h.get("data")))).equals(h.get("mac")), "hmac_streebog256");
        Map<String, String> k = section("kdf_tree_256");
        check(hex(Gost.kdfTree256(hex(k.get("key")), hex(k.get("label")), hex(k.get("seed")))).equals(k.get("out")), "kdf_tree_256");
        byte[] longKey = new byte[83];                                   // keys longer than the block are hashed first
        Arrays.fill(longKey, (byte) 'x');
        check(Arrays.equals(Gost.hmacStreebog256(longKey, new byte[]{1}), Gost.hmacStreebog256(Gost.streebog256(longKey), new byte[]{1})), "hmac long key");

        // Kuznyechik
        Map<String, String> kz = section("kuznyechik");
        Gost.Kuznyechik cipher = new Gost.Kuznyechik(hex(kz.get("key")));
        check(hex(cipher.encryptBlock(hex(kz.get("pt")))).equals(kz.get("ct")), "kuznyechik encrypt");
        check(hex(cipher.decryptBlock(hex(kz.get("ct")))).equals(kz.get("pt")), "kuznyechik decrypt");

        // MGM RFC 9058: encrypt, decrypt, tampering (ciphertext, tag, AAD) refused
        Map<String, String> mg = section("mgm_rfc9058");
        Gost.Kuznyechik mk = new Gost.Kuznyechik(hex(mg.get("key")));
        byte[] nonce = hex(mg.get("nonce")), aad = hex(mg.get("aad")), pt = hex(mg.get("pt"));
        check(mg.get("pt").startsWith("1122334455667700ffeeddccbbaa9988"), "fixture pt is the RFC 9058 A.1 plaintext (byte 14 = 0x99)");
        byte[] sealed = Gost.mgmSeal(mk, nonce, pt, aad);
        check(hex(sealed).equals(mg.get("ct") + mg.get("tag")), "mgm seal: " + hex(sealed));
        check(Arrays.equals(Gost.mgmOpen(mk, nonce, hex(mg.get("ct") + mg.get("tag")), aad), pt), "mgm open of the fixture ct‖tag");
        byte[] tampered = sealed.clone(); tampered[3] ^= 1;
        try { Gost.mgmOpen(mk, nonce, tampered, aad); check(false, "tampered ciphertext must be refused"); } catch (GeneralSecurityException expected) { }
        tampered = sealed.clone(); tampered[sealed.length - 1] ^= 1;
        try { Gost.mgmOpen(mk, nonce, tampered, aad); check(false, "tampered tag must be refused"); } catch (GeneralSecurityException expected) { }
        byte[] badAad = aad.clone(); badAad[0] ^= 1;
        try { Gost.mgmOpen(mk, nonce, sealed, badAad); check(false, "wrong AAD must be refused"); } catch (GeneralSecurityException expected) { }
        byte[] badNonce = nonce.clone(); badNonce[0] |= (byte) 0x80;
        try { Gost.mgmSeal(mk, badNonce, pt, aad); check(false, "nonce with the top bit set must be refused"); } catch (IllegalArgumentException expected) { }

        // Curve: keypair vector, off-curve point refused, VKO vector
        Map<String, String> kp = section("keypair");
        BigInteger d = new BigInteger(1, b64(kp.get("private_b64")));
        BigInteger[] pub = Gost.mul(d, Gost.G);
        check(pub[0].equals(new BigInteger(kp.get("public_x_hex_be").substring(2), 16)), "public X");
        check(pub[1].equals(new BigInteger(kp.get("public_y_hex_be").substring(2), 16)), "public Y");
        check(b64(Gost.encodePoint(pub)).equals(kp.get("public_b64")), "public key encoding (X‖Y little-endian)");
        check(Gost.onCurve(Gost.decodePoint(b64(kp.get("public_b64")))), "fixture public key is on the curve");
        byte[] off = b64(kp.get("public_b64")); off[5] ^= 1;
        try { Gost.decodePoint(off); check(false, "off-curve point must be refused"); } catch (IllegalArgumentException expected) { }
        try { Gost.decodePoint(new byte[32]); check(false, "32-byte point must be refused"); } catch (IllegalArgumentException expected) { }
        Map<String, String> vk = section("vko");
        byte[] kek = Gost.vko(new BigInteger(1, b64(vk.get("private_b64"))), Gost.decodePoint(b64(vk.get("peer_public_b64"))), hex(vk.get("ukm_hex")));
        check(hex(kek).equals(vk.get("kek_hex")), "vko kek: " + hex(kek));
        try { Gost.vko(d, pub, new byte[8]); check(false, "zero UKM must be refused"); } catch (IllegalArgumentException expected) { }

        // generated key pairs: shapes, on the curve, and VKO agrees from both sides
        String[] g1 = Gost.generateGostKeyPair(), g2 = Gost.generateGostKeyPair();
        check(b64(g1[0]).length == 32 && b64(g1[1]).length == 64, "generated GOST key sizes");
        check(!g1[0].equals(g2[0]), "two generated keys differ");
        BigInteger d1 = new BigInteger(1, b64(g1[0])), d2 = new BigInteger(1, b64(g2[0]));
        check(d1.signum() > 0 && d1.compareTo(Gost.Q) < 0, "scalar in [1, q-1]");
        check(b64(Gost.encodePoint(Gost.mul(d1, Gost.G))).equals(g1[1]), "generated public = d·G");
        byte[] ukm = hex("0102030405060708");
        check(Arrays.equals(Gost.vko(d1, Gost.decodePoint(b64(g2[1])), ukm), Gost.vko(d2, Gost.decodePoint(b64(g1[1])), ukm)), "VKO symmetric");

        // Envelope: the fixture decrypts to payload; wrong key, wrong name, tampered ciphertext refused
        Map<String, String> env = section("envelope");
        check("core-db".equals(env.get("name")) && VaultClient.SEALED_ALG_GOST.equals(env.get("alg")), "envelope section parsed");
        Map<String, String> payload = Gost.unsealGost(env, kp.get("private_b64"), env.get("name"));
        check("pg-pass-2026".equals(payload.get("value")) && "core".equals(payload.get("login")) && "123456".equals(payload.get("totp")),
              "envelope payload: " + payload);
        Map<String, String> viaClient = VaultClient.unseal(env, kp.get("private_b64"), env.get("name"));
        check("pg-pass-2026".equals(viaClient.get("value")), "VaultClient.unseal dispatches on alg");
        try { Gost.unsealGost(env, g1[0], env.get("name")); check(false, "wrong key must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "wrong-key message: " + e.getMessage()); }
        try { Gost.unsealGost(env, kp.get("private_b64"), "other-secret"); check(false, "wrong name (AAD) must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "wrong-name message: " + e.getMessage()); }
        Map<String, String> broken = new HashMap<>(env);
        byte[] ct = b64(env.get("ct")); ct[0] ^= 1; broken.put("ct", b64(ct));
        try { Gost.unsealGost(broken, kp.get("private_b64"), env.get("name")); check(false, "tampered envelope must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "tampered message"); }
        broken = new HashMap<>(env); broken.put("epk", b64(off));
        try { Gost.unsealGost(broken, kp.get("private_b64"), env.get("name")); check(false, "off-curve epk must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "off-curve epk message"); }
        try { Gost.unsealGost(env, b64(new byte[16]), env.get("name")); check(false, "16-byte private key must be refused"); }
        catch (IOException e) { check(e.getMessage().contains("32 bytes"), "short key message: " + e.getMessage()); }

        // timing of one unsealGost (after the one above warmed the JIT)
        long t0 = System.nanoTime();
        Gost.unsealGost(env, kp.get("private_b64"), env.get("name"));
        System.out.println("gost: one unsealGost took " + (System.nanoTime() - t0) / 1_000_000.0 + " ms");
    }

    static void reply(com.sun.net.httpserver.HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    public static void main(String[] args) throws Exception {
        // GOST primitives and the server-produced fixture envelope (clients/fixtures/gost-sealed.json)
        fixtureJson = Files.readString(Path.of("../fixtures/gost-sealed.json"), StandardCharsets.UTF_8);
        int si = fixtureJson.indexOf("\"sealed\"");
        gostSealedJson = fixtureJson.substring(si, fixtureJson.indexOf("}", si) + 1);
        long tInit = System.nanoTime();
        Gost.streebog256(new byte[0]);                                   // forces class init (Kuznyechik LS tables)
        System.out.println("gost: class init " + (System.nanoTime() - tInit) / 1_000_000.0 + " ms");
        gostTests();

        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/", ex -> {
            String auth = ex.getRequestHeaders().getFirst("Authorization");
            if (ex.getRequestMethod().equals("POST") && ex.getRequestURI().getPath().equals("/api/enroll")) {   // public: no token yet
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                if (!body.contains("\"code\":\"enr_ok\"")) { reply(ex, 404, "{\"detail\":\"enrolment code is unknown, revoked or expired\"}"); return; }
                check(body.contains("\"public_key\":\"") && body.contains("\"name\":\"host-1\""), "enrol body: " + body);
                reply(ex, 200, "{\"raw_token\":\"vlt_enrolled\",\"token_name\":\"node-host-1\",\"folder_name\":\"f\",\"sealed\":true}");
                return;
            }
            if (!"Bearer vlt_test_token".equals(auth)) { reply(ex, 401, "{\"detail\":\"invalid token\"}"); return; }
            if (failing.get()) { reply(ex, 503, "{}"); return; }
            hits.incrementAndGet();
            String p = ex.getRequestURI().getPath(), m = ex.getRequestMethod();
            if (m.equals("GET") && p.equals("/api/v1/m/secret/db-password")) {
                reply(ex, 200, "{\"name\":\"db-password\",\"value\":\"s3c\\\"ret\",\"login\":\"app\",\"totp\":null,\"updated_at\":\"2026-10-02T00:00:00\"}");
            } else if (m.equals("POST") && p.equals("/api/v1/m/secret/new")) {
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                check(body.contains("\"value\":\"v\"") && body.contains("\"login\":\"u\""), "put body: " + body);
                reply(ex, 200, "{\"id\":7,\"name\":\"new\",\"created\":true}");
            } else if (m.equals("GET") && p.equals("/api/v1/m/secret/core-db")) {
                // sealed by the server (backend/sealed.py) for the private key 0x01..0x20
                reply(ex, 200, "{\"name\":\"core-db\",\"version\":1,\"current_version\":1,\"updated_at\":\"x\",\"sealed\":{\"alg\":\"X25519-HKDF-SHA256-AES256GCM\",\"v\":1,\"epk\":\"qId7VmcoFhnApxHZznkoaKFl/wIl/z2HauZI+GMVI1Q=\",\"nonce\":\"qTsci1J2iUT0nr58\",\"ct\":\"DmXYnxSzPc9d6MIdODi2I9bd2nw4yi3mBUWcxVHLDVlX/ax+BH5DcqBh2PBcBt8E7eTZouxd0SyW+fzJ4dlXL+F4SL2HrSY=\"}}");
            } else if (m.equals("GET") && p.equals("/api/v1/m/secret/core-db-gost")) {
                // the GOST envelope from the fixture file, sealed by the server for the same private key 0x01..0x20
                reply(ex, 200, "{\"name\":\"core-db\",\"version\":1,\"current_version\":1,\"updated_at\":\"x\"," + gostSealedJson + "}");
            } else if (p.equals("/api/v1/m/health")) {
                reply(ex, 200, "{\"status\":\"ok\",\"scope_folder\":\"f\"}");
            } else {
                reply(ex, 404, "{\"detail\":\"not found\"}");
            }
        });
        srv.start();
        String base = "http://127.0.0.1:" + srv.getAddress().getPort();
        try {
            // token shape
            try { new VaultClient(base, "my master password"); check(false, "master password accepted"); }
            catch (IllegalArgumentException expected) { }

            // cache TTL must comfortably exceed JVM warm-up of the first request; expiry is tested below with a sleep
            VaultClient v = new VaultClient(base, "vlt_test_token", Duration.ofSeconds(2), Duration.ofSeconds(2), 1, true);
            check("s3c\"ret".equals(v.get("db-password")), "value with escaped quote");
            check("app".equals(v.getFull("db-password").login), "login field");
            check(v.getFull("db-password").totp == null, "null totp");
            v.get("db-password");
            check(hits.get() == 1, "second get must come from cache, hits=" + hits.get());

            // fail-open: vault down, cache expired → stale value
            Thread.sleep(2200);
            failing.set(true);
            check("s3c\"ret".equals(v.get("db-password")), "fail-open stale value");
            try { v.get("never-seen"); check(false, "uncached secret while down must fail"); }
            catch (IOException expected) { }
            failing.set(false);

            // 404 carries status and is not retried
            int before = hits.get();
            try { v.get("missing"); check(false, "404 expected"); }
            catch (VaultClient.VaultException e) { check(e.status == 404, "status 404"); }
            check(hits.get() == before + 1, "404 must not be retried");

            // sealed delivery: the server fixture opens with the bound key, and only with it
            String fixtureSK = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
            VaultClient sealed = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, fixtureSK);
            VaultClient.Secret cs = sealed.getFull("core-db");
            check("pg-pass-2026".equals(cs.value) && "core".equals(cs.login) && "123456".equals(cs.totp), "sealed payload: " + cs.value + "/" + cs.login + "/" + cs.totp);
            check("123456".equals(sealed.totp("core-db").orElse(null)), "sealed totp");
            VaultClient wrongKey = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, VaultClient.generateKeyPair()[0]);
            try { wrongKey.get("core-db"); check(false, "another key must not open the envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "wrong-key message: " + e.getMessage()); }
            VaultClient noKey = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, null);
            try { noKey.get("core-db"); check(false, "without a key the client must refuse"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("sealed values"), "no-key message: " + e.getMessage()); }
            String[] kp = VaultClient.generateKeyPair();
            check(java.util.Base64.getDecoder().decode(kp[0]).length == 32 && java.util.Base64.getDecoder().decode(kp[1]).length == 32, "key pair is raw 32 bytes each");

            // GOST sealed delivery through the client: same key, the envelope's alg selects the GOST path
            VaultClient.Secret gs = sealed.getFull("core-db-gost");
            check("pg-pass-2026".equals(gs.value) && "core".equals(gs.login) && "123456".equals(gs.totp), "gost sealed payload: " + gs.value + "/" + gs.login + "/" + gs.totp);
            check("core-db".equals(gs.name), "gost sealed name kept");
            check("123456".equals(sealed.totp("core-db-gost").orElse(null)), "gost sealed totp");
            VaultClient wrongGost = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, VaultClient.generateGostKeyPair()[0]);
            try { wrongGost.get("core-db-gost"); check(false, "another GOST key must not open the envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "gost wrong-key message: " + e.getMessage()); }
            try { wrongGost.get("core-db"); check(false, "a GOST key must not open the X25519 envelope"); }
            catch (IOException expected) { }
            try { noKey.get("core-db-gost"); check(false, "without a key the client must refuse the GOST envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("sealed values"), "gost no-key message"); }
            String[] gkp = VaultClient.generateGostKeyPair();
            check(java.util.Base64.getDecoder().decode(gkp[0]).length == 32 && java.util.Base64.getDecoder().decode(gkp[1]).length == 64, "GOST key pair is 32 + 64 raw bytes");

            // enrolment: local key pair, token sealed to it; a bad code is a 404
            String[] en = VaultClient.enroll(base, "enr_ok", "host-1", false);
            check("vlt_enrolled".equals(en[0]) && java.util.Base64.getDecoder().decode(en[1]).length == 32 && "node-host-1".equals(en[3]), "enrol result");
            String[] eg = VaultClient.enroll(base, "enr_ok", "host-1", true);
            check(java.util.Base64.getDecoder().decode(eg[2]).length == 64, "gost enrol public key is 64 bytes");
            try { VaultClient.enroll(base, "enr_bad", "host-1", false); check(false, "bad code must fail"); }
            catch (VaultClient.VaultException e) { check(e.status == 404, "enrol 404"); }

            v.put("new", "v", "u", "", "");
            check(v.health().contains("\"status\":\"ok\""), "health");

            // 401
            VaultClient bad = new VaultClient(base, "vlt_wrong");
            try { bad.get("db-password"); check(false, "401 expected"); }
            catch (VaultClient.VaultException e) { check(e.status == 401, "status 401"); }

            // flat JSON parser corner cases
            var m = VaultClient.parseFlat("{\"a\":\"x\\u0041\\n\",\"n\":12,\"t\":true,\"z\":null}");
            check("xA\n".equals(m.get("a")) && "12".equals(m.get("n")) && "true".equals(m.get("t")) && m.containsKey("z") && m.get("z") == null, "parseFlat");
            System.out.println("VaultClientTest: OK");
        } finally {
            srv.stop(0);
        }
    }
}
