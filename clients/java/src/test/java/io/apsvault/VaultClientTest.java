package io.apsvault;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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

    // ── P-256 (0.22): fixture clients/fixtures/p256-sealed.json, a software sealer, and the hardware key ──
    static String p256Json;          // whole fixture file
    static String p256SealedJson;    // its "sealed": {...} object as text, served by the fake vault
    static volatile String hwSealedJson;   // "sealed": {...} for the hardware key's point, set by the hardware test

    static Map<String, String> p256Section(String key) {
        int i = p256Json.indexOf("\"" + key + "\"");
        check(i >= 0, "p256 fixture section " + key);
        return VaultClient.parseFlat(p256Json.substring(i, p256Json.indexOf("}", i) + 1));
    }

    static ECParameterSpec p256() throws GeneralSecurityException {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        return ap.getParameterSpec(ECParameterSpec.class);
    }

    /** What the vault does (backend/sealed.py seal_p256), in software: ephemeral ECDH to the client's point,
     *  HKDF-SHA256(info = label ‖ epk ‖ client point), AES-256-GCM with the name as AAD. */
    static Map<String, String> sealP256(byte[] clientPoint, String name, String payloadJson) throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "SunEC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair eph = g.generateKeyPair();
        byte[] epk = VaultClient.encodePoint(((ECPublicKey) eph.getPublic()).getW());
        PublicKey peer = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(VaultClient.decodePoint(clientPoint), p256()));
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "SunEC");
        ka.init(eph.getPrivate()); ka.doPhase(peer, true);
        byte[] info = new byte[0];
        for (byte[] part : new byte[][]{"aps-vault/sealed-p256/v1".getBytes(StandardCharsets.UTF_8), epk, clientPoint}) {
            byte[] r = Arrays.copyOf(info, info.length + part.length); System.arraycopy(part, 0, r, info.length, part.length); info = r;
        }
        byte[] key = VaultClient.hkdf(ka.generateSecret(), info, 32);
        byte[] nonce = new byte[12]; new SecureRandom().nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD(name.getBytes(StandardCharsets.UTF_8));
        byte[] ct = c.doFinal(payloadJson.getBytes(StandardCharsets.UTF_8));
        Map<String, String> env = new HashMap<>();
        env.put("alg", VaultClient.SEALED_ALG_P256); env.put("v", "1");
        env.put("epk", b64(epk)); env.put("nonce", b64(nonce)); env.put("ct", b64(ct));
        return env;
    }

    static String sealedJson(Map<String, String> env) {
        return "\"sealed\":{\"alg\":\"" + env.get("alg") + "\",\"v\":1,\"epk\":\"" + env.get("epk") + "\",\"nonce\":\"" + env.get("nonce") + "\",\"ct\":\"" + env.get("ct") + "\"}";
    }

    static void p256Tests() throws Exception {
        // the server-produced fixture: scalar 0x01..0x20 ‖ its point is this client's private string
        Map<String, String> kp = p256Section("keypair");
        byte[] scalar = b64(kp.get("private_b64")), point = b64(kp.get("public_b64"));
        check(scalar.length == 32 && point.length == 65 && point[0] == 4, "fixture key shapes");
        byte[] priv = Arrays.copyOf(scalar, 97); System.arraycopy(point, 0, priv, 32, 65);
        String privB64 = b64(priv);
        Map<String, String> env = VaultClient.parseFlat(p256SealedJson);
        check(VaultClient.SEALED_ALG_P256.equals(env.get("alg")) && "1".equals(env.get("v")), "fixture envelope parsed: " + env);
        Map<String, String> payload = VaultClient.unseal(env, privB64, "core-db");
        check("pg-pass-2026".equals(payload.get("value")) && "core".equals(payload.get("login")) && "123456".equals(payload.get("totp")),
              "p256 fixture payload: " + payload);
        Map<String, String> expected = p256Section("payload");
        check(expected.get("value").equals(payload.get("value")) && expected.get("login").equals(payload.get("login")), "payload equals the fixture's payload section");

        // a bare 32-byte scalar is refused with a pointer to generateP256KeyPair(); other shapes are refused too
        try { VaultClient.unseal(env, kp.get("private_b64"), "core-db"); check(false, "bare scalar must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("97 bytes") && e.getMessage().contains("generateP256KeyPair"), "scalar-only message: " + e.getMessage()); }
        try { VaultClient.unseal(env, b64(new byte[97]), "core-db"); check(false, "97 zero bytes (no 0x04) must be refused"); }
        catch (IOException e) { check(e.getMessage().contains("97 bytes"), "bad shape message: " + e.getMessage()); }

        // wrong key, wrong name, tampered ciphertext, tampered tag, off-curve ephemeral point → "does not open"
        String[] other = VaultClient.generateP256KeyPair();
        try { VaultClient.unseal(env, other[0], "core-db"); check(false, "another P-256 key must not open the fixture"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "wrong-key message: " + e.getMessage()); }
        try { VaultClient.unseal(env, privB64, "other-secret"); check(false, "wrong name (AAD) must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "wrong-name message: " + e.getMessage()); }
        Map<String, String> broken = new HashMap<>(env);
        byte[] ct = b64(env.get("ct")); ct[0] ^= 1; broken.put("ct", b64(ct));
        try { VaultClient.unseal(broken, privB64, "core-db"); check(false, "tampered ciphertext must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "tampered ct message"); }
        broken = new HashMap<>(env); ct = b64(env.get("ct")); ct[ct.length - 1] ^= 1; broken.put("ct", b64(ct));
        try { VaultClient.unseal(broken, privB64, "core-db"); check(false, "tampered tag must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "tampered tag message"); }
        broken = new HashMap<>(env); byte[] epk = b64(env.get("epk")); epk[7] ^= 1; broken.put("epk", b64(epk));
        try { VaultClient.unseal(broken, privB64, "core-db"); check(false, "off-curve epk must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "off-curve epk message: " + e.getMessage()); }
        broken = new HashMap<>(env); broken.put("epk", b64(Arrays.copyOf(epk, 33)));
        try { VaultClient.unseal(broken, privB64, "core-db"); check(false, "33-byte epk must be refused"); }
        catch (IOException e) { check(e.getMessage().contains("65 bytes"), "short epk message: " + e.getMessage()); }

        // generated pair: shapes, the public half is the point inside the private string, round trip through the sealer
        String[] g = VaultClient.generateP256KeyPair();
        byte[] gp = b64(g[0]);
        check(gp.length == 97 && b64(g[1]).length == 65 && gp[32] == 4, "generated P-256 key sizes 97 / 65");
        check(Arrays.equals(Arrays.copyOfRange(gp, 32, 97), b64(g[1])), "public = point part of private");
        check(!g[0].equals(other[0]), "two generated keys differ");
        Map<String, String> sealed = sealP256(b64(g[1]), "svc-db", "{\"value\":\"v\\\"1\",\"login\":\"u\",\"notes\":\"n\"}");
        Map<String, String> rt = VaultClient.unseal(sealed, g[0], "svc-db");
        check("v\"1".equals(rt.get("value")) && "u".equals(rt.get("login")) && "n".equals(rt.get("notes")), "round trip payload: " + rt);
        try { VaultClient.unseal(sealed, other[0], "svc-db"); check(false, "the other generated key must not open it"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "round-trip wrong key"); }
        // the fixture's point sealed by our sealer opens with the fixture key — sealer and unsealer agree with the server
        Map<String, String> toFixture = sealP256(point, "core-db", "{\"value\":\"x\"}");
        check("x".equals(VaultClient.unseal(toFixture, privB64, "core-db").get("value")), "test sealer agrees with the fixture key");

        long t0 = System.nanoTime();
        VaultClient.unseal(env, privB64, "core-db");
        long t1 = System.nanoTime();
        for (int i = 0; i < 20; i++) VaultClient.unseal(env, privB64, "core-db");
        System.out.println("p256: one software unseal took " + (t1 - t0) / 1_000_000.0 + " ms, average of 20 more " + (System.nanoTime() - t1) / 20_000_000.0 + " ms");
    }

    /** The reason the P-256 envelope exists: the key sits in a PKCS#11 token (SoftHSM2 here, a TPM in life), reached
     *  through SunPKCS11. Needs VAULT_TEST_PKCS11_CONF (SunPKCS11 config) and a token holding key+certificate
     *  "vault-node" with PIN 1234; VAULT_TEST_PKCS11_PUB (DER SubjectPublicKeyInfo) overrides the certificate's point. */
    static void hardwareTests(String base, Map<String, String> fixtureEnv) throws Exception {
        String conf = System.getenv("VAULT_TEST_PKCS11_CONF");
        if (conf == null || conf.isEmpty()) { System.out.println("SKIPPED: VAULT_TEST_PKCS11_CONF not set"); return; }
        Provider p = Security.getProvider("SunPKCS11").configure(conf);
        Security.addProvider(p);
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, "1234".toCharArray());
        check(Collections.list(ks.aliases()).contains("vault-node"), "token must expose alias vault-node (private key + certificate with the same CKA_ID), aliases=" + Collections.list(ks.aliases()));
        PrivateKey k = (PrivateKey) ks.getKey("vault-node", "1234".toCharArray());
        check(k != null && "EC".equals(k.getAlgorithm()), "hardware key: " + k);
        check(k.getFormat() == null || k.getEncoded() == null, "the key must not be exportable, format=" + k.getFormat());
        byte[] point;
        String pubPath = System.getenv("VAULT_TEST_PKCS11_PUB");
        if (pubPath != null && !pubPath.isEmpty()) {
            ECPublicKey pub = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(Path.of(pubPath))));
            point = VaultClient.encodePoint(pub.getW());
            java.security.cert.Certificate cert = ks.getCertificate("vault-node");
            if (cert != null) check(Arrays.equals(point, VaultClient.encodePoint(((ECPublicKey) cert.getPublicKey()).getW())), "certificate's point equals the token's public key object");
        } else {
            point = VaultClient.encodePoint(((ECPublicKey) ks.getCertificate("vault-node").getPublicKey()).getW());
        }
        check(point.length == 65 && point[0] == 4, "hardware public point");

        // direct: seal to the token's point in software, open with the token's private key handle
        Map<String, String> env = sealP256(point, "hw-secret", "{\"value\":\"tpm-pass\",\"login\":\"node\"}");
        Map<String, String> out = VaultClient.unsealP256(env, k, point, "hw-secret");
        check("tpm-pass".equals(out.get("value")) && "node".equals(out.get("login")), "hardware unseal payload: " + out);
        try { VaultClient.unsealP256(env, k, point, "other"); check(false, "wrong name must be refused on the hardware path"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "hw wrong-name message"); }
        try { VaultClient.unsealP256(fixtureEnv, k, point, "core-db"); check(false, "the fixture (sealed to the software key) must not open with the hardware key"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "hw wrong-key message"); }
        byte[] wrongPoint = b64(VaultClient.generateP256KeyPair()[1]);
        try { VaultClient.unsealP256(env, k, wrongPoint, "hw-secret"); check(false, "a foreign public point in the HKDF info must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "hw wrong-point message"); }

        // through the client: withKeyProvider + the fake vault serving the envelope; a non-P-256 envelope is refused
        hwSealedJson = sealedJson(env);
        VaultClient hw = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, null).withKeyProvider(k, point);
        VaultClient.Secret s = hw.getFull("hw-secret");
        check("tpm-pass".equals(s.value) && "node".equals(s.login) && "hw-secret".equals(s.name), "hw client payload: " + s.value + "/" + s.login);
        try { hw.get("core-db"); check(false, "a hardware key must refuse the X25519 envelope"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("opens only the P-256 envelope") && e.getMessage().contains("X25519-HKDF-SHA256-AES256GCM"), "hw non-P256 message: " + e.getMessage()); }
        try { hw.get(env("gost")); check(false, "a hardware key must refuse the GOST envelope"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("opens only the P-256 envelope"), "hw gost message"); }
        try { hw.get(env("p256")); check(false, "the fixture envelope is bound to the software key, not the token"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "hw fixture message"); }
        try { hw.withKeyProvider(k, Arrays.copyOf(point, 64)); check(false, "64-byte point must be refused"); }
        catch (IllegalArgumentException expected) { }
        try { hw.withKeyProvider(KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate(), point); check(false, "RSA key must be refused"); }
        catch (IllegalArgumentException expected) { }

        // enrolment with the hardware key: the public point goes up, nothing private comes back
        String[] en = VaultClient.enroll(base, "enr_ok", "host-1", k, point);
        check("vlt_enrolled".equals(en[0]) && "".equals(en[1]) && b64(point).equals(en[2]) && "node-host-1".equals(en[3]), "hw enrol result");

        long t0 = System.nanoTime();
        VaultClient.unsealP256(env, k, point, "hw-secret");
        long t1 = System.nanoTime();
        for (int i = 0; i < 20; i++) VaultClient.unsealP256(env, k, point, "hw-secret");
        System.out.println("p256 via SunPKCS11/SoftHSM2: ok (" + p.getName() + ", key " + k.getClass().getSimpleName() + "), one hardware unseal took "
                + (t1 - t0) / 1_000_000.0 + " ms, average of 20 more " + (System.nanoTime() - t1) / 20_000_000.0 + " ms");
    }

    // ── post-quantum hybrid (0.27): fixture clients/fixtures/pqc-sealed.json, X25519 + ML-KEM-768 ──
    static String pqcJson;           // whole fixture file
    static String pqcSealedJson;     // the first envelope's "sealed": {...} object as text, served by the fake vault
    static final String PQC_SKIP = "SKIPPED: ML-KEM not available in this JDK (needs 24+)";

    static Map<String, String> pqcSection(String key) {
        int i = pqcJson.indexOf("\"" + key + "\"");
        check(i >= 0, "pqc fixture section " + key);
        return VaultClient.parseFlat(pqcJson.substring(i, pqcJson.indexOf("}", i) + 1));
    }

    /** One entry of the fixture's "envelopes" array. */
    static final class PqcEnvelope {
        final String name; final Map<String, String> payload, sealed;
        PqcEnvelope(String name, Map<String, String> payload, Map<String, String> sealed) { this.name = name; this.payload = payload; this.sealed = sealed; }
    }

    static java.util.List<PqcEnvelope> pqcEnvelopes() {
        java.util.List<PqcEnvelope> out = new java.util.ArrayList<>();
        int pos = pqcJson.indexOf("\"envelopes\"");
        check(pos >= 0, "pqc fixture has envelopes");
        while (true) {
            int ni = pqcJson.indexOf("\"name\"", pos);
            if (ni < 0) break;
            int pi = pqcJson.indexOf("\"payload\"", ni), si = pqcJson.indexOf("\"sealed\"", pi);
            String name = VaultClient.parseFlat(pqcJson.substring(ni, pi)).get("name");
            Map<String, String> payload = VaultClient.parseFlat(pqcJson.substring(pi, pqcJson.indexOf("}", pi) + 1));
            Map<String, String> sealed = VaultClient.parseFlat(pqcJson.substring(si, pqcJson.indexOf("}", si) + 1));
            out.add(new PqcEnvelope(name, payload, sealed));
            pos = pqcJson.indexOf("}", si) + 1;
        }
        return out;
    }

    /** What the vault does (backend/sealed.py seal_pqc), in software: ephemeral X25519 with the client's X25519 half,
     *  ML-KEM-768 encapsulation to the client's encapsulation key, HKDF-SHA256(ss_x ‖ ss_kem, info = label ‖ epk ‖ kem),
     *  AES-256-GCM with the name as AAD. Needs ML-KEM in the JDK. */
    static Map<String, String> sealPqc(byte[] clientPub, String name, String payloadJson) throws GeneralSecurityException {
        check(clientPub.length == 1216, "hybrid public key is 1216 bytes");
        KeyPairGenerator g = KeyPairGenerator.getInstance("XDH");
        g.initialize(java.security.spec.NamedParameterSpec.X25519);
        KeyPair eph = g.generateKeyPair();
        byte[] epkEnc = eph.getPublic().getEncoded(), epk = Arrays.copyOfRange(epkEnc, epkEnc.length - 32, epkEnc.length);
        KeyFactory kf = KeyFactory.getInstance("XDH");
        PublicKey peer = kf.generatePublic(new X509EncodedKeySpec(MlKem.concat(hex("302a300506032b656e032100"), Arrays.copyOf(clientPub, 32))));
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(eph.getPrivate()); ka.doPhase(peer, true);
        byte[] ssX = ka.generateSecret();
        byte[][] kem = MlKem.encapsulate(MlKem.publicFromEk(Arrays.copyOfRange(clientPub, 32, 1216)));   // {ct, ss}
        byte[] info = MlKem.concat(MlKem.concat("aps-vault/sealed-pqc/v1".getBytes(StandardCharsets.UTF_8), epk), kem[0]);
        byte[] key = VaultClient.hkdf(MlKem.concat(ssX, kem[1]), info, 32);
        byte[] nonce = new byte[12]; new SecureRandom().nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD(name.getBytes(StandardCharsets.UTF_8));
        byte[] ct = c.doFinal(payloadJson.getBytes(StandardCharsets.UTF_8));
        Map<String, String> env = new HashMap<>();
        env.put("alg", VaultClient.SEALED_ALG_PQC); env.put("v", "1");
        env.put("epk", b64(epk)); env.put("kem", b64(kem[0])); env.put("nonce", b64(nonce)); env.put("ct", b64(ct));
        return env;
    }

    static void pqcTests() throws Exception {
        Map<String, String> kp = pqcSection("keypair");
        byte[] priv = b64(kp.get("private_b64")), pub = b64(kp.get("public_b64"));
        check(priv.length == 96 && pub.length == 1216, "fixture hybrid key shapes 96 / 1216");
        check(Arrays.equals(Arrays.copyOf(priv, 32), hex(kp.get("x25519_sk_hex"))) && Arrays.equals(Arrays.copyOfRange(priv, 32, 96), hex(kp.get("mlkem_seed_hex"))), "private = x25519 sk ‖ ml-kem seed");
        java.util.List<PqcEnvelope> envelopes = pqcEnvelopes();
        check(envelopes.size() == 2, "fixture has two envelopes, got " + envelopes.size());

        // The parts that need no ML-KEM in the JDK: this client's own Keccak and FIPS 203 KeyGen.
        // SHAKE against the FIPS 202 empty-message vectors, then streaming squeeze consistency.
        check(hex(new MlKem.Shake(128).squeeze(32)).equals("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"), "SHAKE128('') vector");
        check(hex(new MlKem.Shake(256).squeeze(64)).equals("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"), "SHAKE256('') vector");
        byte[] msg = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);
        MlKem.Shake s1 = new MlKem.Shake(128); s1.absorb(msg);
        check(hex(s1.squeeze(32)).equals("f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e"), "SHAKE128(fox) vector");
        MlKem.Shake s2 = new MlKem.Shake(128); s2.absorb(msg); byte[] part = MlKem.concat(s2.squeeze(1), s2.squeeze(500));
        MlKem.Shake s3 = new MlKem.Shake(128); s3.absorb(msg);
        check(Arrays.equals(part, s3.squeeze(501)), "squeeze in pieces equals one squeeze across block boundaries");
        // pqcPublicFromPrivate(fixture private) == fixture public — the ML-KEM half is derived from the seed by MlKem.publicFromSeed
        long t0 = System.nanoTime();
        String derived = VaultClient.pqcPublicFromPrivate(kp.get("private_b64"));
        long tDerive = System.nanoTime() - t0;
        check(derived.equals(kp.get("public_b64")), "pqcPublicFromPrivate(fixture) equals the fixture public key");
        check(Arrays.equals(MlKem.publicFromSeed(hex(kp.get("mlkem_seed_hex"))), Arrays.copyOfRange(pub, 32, 1216)), "ML-KEM ek from the seed alone");
        byte[] otherSeed = Arrays.copyOfRange(priv, 32, 96); otherSeed[0] ^= 1;
        check(!Arrays.equals(MlKem.publicFromSeed(otherSeed), Arrays.copyOfRange(pub, 32, 1216)), "a different seed gives a different ek");
        try { VaultClient.pqcPublicFromPrivate(b64(new byte[32])); check(false, "32-byte key must be refused by pqcPublicFromPrivate"); }
        catch (IOException e) { check(e.getMessage().contains("96 bytes"), "pqcPublicFromPrivate shape message: " + e.getMessage()); }
        System.out.println("pqc: SHAKE vectors ok, pqcPublicFromPrivate(fixture) == fixture public (" + tDerive / 1_000_000.0 + " ms)");

        Map<String, String> env0 = envelopes.get(0).sealed;
        if (!MlKem.available()) {
            // Java 11–23: the hybrid envelope must fail with a clear pointer, never silently
            try { VaultClient.unseal(env0, kp.get("private_b64"), envelopes.get(0).name); check(false, "unseal must fail without ML-KEM"); }
            catch (IOException e) { check(e.getMessage().contains("Java 24+") && e.getMessage().contains("ML-KEM"), "no-ML-KEM unseal message: " + e.getMessage()); }
            try { VaultClient.generatePqcKeyPair(); check(false, "generatePqcKeyPair must fail without ML-KEM"); }
            catch (GeneralSecurityException e) { check(e.getMessage().contains("Java 24+"), "no-ML-KEM keygen message: " + e.getMessage()); }
            System.out.println(PQC_SKIP);
            return;
        }

        // every fixture envelope opens to exactly its payload (the second one has a Cyrillic name and value)
        for (PqcEnvelope e : envelopes) {
            String name = e.name;
            Map<String, String> expected = e.payload, env = e.sealed;
            check(VaultClient.SEALED_ALG_PQC.equals(env.get("alg")) && "1".equals(env.get("v")) && b64(env.get("kem")).length == 1088 && b64(env.get("epk")).length == 32, "fixture envelope shape for " + name);
            Map<String, String> payload = VaultClient.unseal(env, kp.get("private_b64"), name);
            check(payload.size() == expected.size(), "payload keys for " + name + ": " + payload.keySet() + " vs " + expected.keySet());
            for (Map.Entry<String, String> kv : expected.entrySet())
                check(kv.getValue().equals(payload.get(kv.getKey())), name + " payload." + kv.getKey() + " = " + payload.get(kv.getKey()) + ", expected " + kv.getValue());
        }
        check("pg-pass-2026".equals(VaultClient.unseal(env0, kp.get("private_b64"), "core-db").get("value")), "first envelope value");
        PqcEnvelope cyr = envelopes.get(1);
        check(cyr.name.contains("кириллица") && "значение №2 ✓".equals(VaultClient.unseal(cyr.sealed, kp.get("private_b64"), cyr.name).get("value")), "Cyrillic envelope value");

        // negatives: flipped byte in kem (implicit rejection → wrong secret), epk, ct, tag; wrong name; wrong key; key shapes
        for (String field : new String[]{"kem", "epk", "ct"}) {
            Map<String, String> broken = new HashMap<>(env0);
            byte[] b = b64(env0.get(field)); b[b.length / 2] ^= 1; broken.put(field, b64(b));
            try { VaultClient.unseal(broken, kp.get("private_b64"), "core-db"); check(false, "flipped byte in " + field + " must be refused"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "flipped " + field + " message: " + e.getMessage()); }
        }
        Map<String, String> broken = new HashMap<>(env0); byte[] ct = b64(env0.get("ct")); ct[ct.length - 1] ^= 1; broken.put("ct", b64(ct));
        try { VaultClient.unseal(broken, kp.get("private_b64"), "core-db"); check(false, "tampered tag must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "tampered tag message"); }
        try { VaultClient.unseal(env0, kp.get("private_b64"), "other-secret"); check(false, "wrong name (AAD) must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "wrong-name message: " + e.getMessage()); }
        String[] other = VaultClient.generatePqcKeyPair();
        try { VaultClient.unseal(env0, other[0], "core-db"); check(false, "another hybrid key must not open the fixture"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "wrong-key message: " + e.getMessage()); }
        byte[] halfWrong = priv.clone(); halfWrong[40] ^= 1;                        // right X25519 half, wrong ML-KEM seed
        try { VaultClient.unseal(env0, b64(halfWrong), "core-db"); check(false, "a wrong ML-KEM half alone must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "wrong ml-kem half message"); }
        halfWrong = priv.clone(); halfWrong[3] ^= 1;                                // right ML-KEM half, wrong X25519 half
        try { VaultClient.unseal(env0, b64(halfWrong), "core-db"); check(false, "a wrong X25519 half alone must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "wrong x25519 half message"); }
        try { VaultClient.unseal(env0, b64(new byte[32]), "core-db"); check(false, "32-byte key must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("96 bytes") && e.getMessage().contains("generatePqcKeyPair"), "32-byte key message: " + e.getMessage()); }
        try { VaultClient.unseal(env0, kp.get("private_b64").substring(0, 44), "core-db"); check(false, "the X25519 half alone must be refused"); }
        catch (IOException e) { check(e.getMessage().contains("96 bytes") || e.getMessage().contains("base64") || e.getMessage().contains("Input"), "truncated key message: " + e.getMessage()); }
        broken = new HashMap<>(env0); broken.put("kem", b64(Arrays.copyOf(b64(env0.get("kem")), 1087)));
        try { VaultClient.unseal(broken, kp.get("private_b64"), "core-db"); check(false, "1087-byte kem must be refused"); }
        catch (IOException e) { check(e.getMessage().contains("1088-byte kem"), "short kem message: " + e.getMessage()); }
        broken = new HashMap<>(env0); broken.remove("kem");
        try { VaultClient.unseal(broken, kp.get("private_b64"), "core-db"); check(false, "missing kem must be refused"); }
        catch (IOException e) { check(e.getMessage().contains("'kem' missing"), "missing kem message: " + e.getMessage()); }

        // generated pair: shapes, public derivable from private, round trip through the test sealer, foreign key refused
        String[] g = VaultClient.generatePqcKeyPair();
        check(b64(g[0]).length == 96 && b64(g[1]).length == 1216, "generated hybrid key sizes 96 / 1216");
        check(!g[0].equals(other[0]), "two generated keys differ");
        check(VaultClient.pqcPublicFromPrivate(g[0]).equals(g[1]), "generated public == pqcPublicFromPrivate(generated private)");
        Map<String, String> sealed = sealPqc(b64(g[1]), "svc-db", "{\"value\":\"v\\\"1\",\"login\":\"u\",\"notes\":\"n\"}");
        Map<String, String> rt = VaultClient.unseal(sealed, g[0], "svc-db");
        check("v\"1".equals(rt.get("value")) && "u".equals(rt.get("login")) && "n".equals(rt.get("notes")), "round trip payload: " + rt);
        try { VaultClient.unseal(sealed, other[0], "svc-db"); check(false, "the other generated key must not open it"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "round-trip wrong key"); }
        // sealed by our sealer to the fixture's public key → opens with the fixture private key: sealer and unsealer agree with the server
        Map<String, String> toFixture = sealPqc(pub, "core-db", "{\"value\":\"x\"}");
        check("x".equals(VaultClient.unseal(toFixture, kp.get("private_b64"), "core-db").get("value")), "test sealer agrees with the fixture key");

        t0 = System.nanoTime();
        VaultClient.unseal(env0, kp.get("private_b64"), "core-db");
        long t1 = System.nanoTime();
        for (int i = 0; i < 20; i++) VaultClient.unseal(env0, kp.get("private_b64"), "core-db");
        System.out.println("pqc: one hybrid unseal took " + (t1 - t0) / 1_000_000.0 + " ms, average of 20 more " + (System.nanoTime() - t1) / 20_000_000.0 + " ms");
    }

    static void reply(com.sun.net.httpserver.HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    /** 0.28.2: parseFlat must not recurse per character — a 200 KB string value is parsed on a thread with a
     *  256 KB stack (the CI runner's main thread overflowed on a 1.5 KB `kem` with the old pattern). */
    static void parseFlatSmallStack() throws Exception {
        StringBuilder big = new StringBuilder("{\"name\":\"x\",\"kem\":\"");
        for (int i = 0; i < 200_000; i++) big.append((char) ('A' + i % 26));
        big.append("\",\"esc\":\"a\\\"b\\\\c\",\"version\":7,\"flag\":true,\"none\":null}");
        final String json = big.toString();
        final Throwable[] failure = new Throwable[1];
        @SuppressWarnings("unchecked") final Map<String, String>[] out = new Map[1];
        Thread t = new Thread(null, () -> { try { out[0] = VaultClient.parseFlat(json); } catch (Throwable e) { failure[0] = e; } }, "small-stack", 256 * 1024);
        t.start(); t.join();
        if (failure[0] != null) throw new AssertionError("parseFlat failed on a small stack: " + failure[0], failure[0]);
        check(out[0].get("kem").length() == 200_000, "long value parsed whole");
        check("a\"b\\c".equals(out[0].get("esc")), "escapes still unescaped");
        check("7".equals(out[0].get("version")) && "true".equals(out[0].get("flag")) && out[0].containsKey("none") && out[0].get("none") == null, "numbers, booleans, null");
        System.out.println("parseFlat: 200 KB value on a 256 KB stack ok");
    }

    // ── GOST post-quantum hybrid (0.32): fixture clients/fixtures/gost-pqc-sealed.json ──
    static String gostPqcJson;

    static Map<String, String> gostPqcSection(String key) {
        int i = gostPqcJson.indexOf("\"" + key + "\"");
        check(i >= 0, "gost-pqc fixture section " + key);
        return VaultClient.parseFlat(gostPqcJson.substring(i, gostPqcJson.indexOf("}", i) + 1));
    }

    static java.util.List<PqcEnvelope> gostPqcEnvelopes() {
        java.util.List<PqcEnvelope> out = new java.util.ArrayList<>();
        int pos = gostPqcJson.indexOf("\"envelopes\"");
        check(pos >= 0, "gost-pqc fixture has envelopes");
        while (true) {
            int ni = gostPqcJson.indexOf("\"name\"", pos);
            if (ni < 0) break;
            int pi = gostPqcJson.indexOf("\"payload\"", ni), si = gostPqcJson.indexOf("\"sealed\"", pi);
            String name = VaultClient.parseFlat(gostPqcJson.substring(ni, pi)).get("name");
            Map<String, String> payload = VaultClient.parseFlat(gostPqcJson.substring(pi, gostPqcJson.indexOf("}", pi) + 1));
            Map<String, String> sealed = VaultClient.parseFlat(gostPqcJson.substring(si, gostPqcJson.indexOf("}", si) + 1));
            out.add(new PqcEnvelope(name, payload, sealed));
            pos = gostPqcJson.indexOf("}", si) + 1;
        }
        return out;
    }

    static void gostPqcTests() throws Exception {
        Map<String, String> kp = gostPqcSection("keypair");
        byte[] priv = b64(kp.get("private_b64")), pub = b64(kp.get("public_b64"));
        check(priv.length == 96 && pub.length == 1248, "fixture GOST hybrid key shapes 96 / 1248");
        check(Arrays.equals(Arrays.copyOf(priv, 32), hex(kp.get("gost_sk_hex"))) && Arrays.equals(Arrays.copyOfRange(priv, 32, 96), hex(kp.get("mlkem_seed_hex"))), "private = gost scalar ‖ ml-kem seed");
        java.util.List<PqcEnvelope> envelopes = gostPqcEnvelopes();
        check(envelopes.size() == 2, "gost-pqc fixture has two envelopes, got " + envelopes.size());
        check(VaultClient.gostPqcPublicFromPrivate(kp.get("private_b64")).equals(kp.get("public_b64")), "gostPqcPublicFromPrivate(fixture) equals the fixture public key");
        // the GOST half is the plain GOST fixture scalar → the first 64 public bytes are that fixture's point
        Map<String, String> gkp = VaultClient.parseFlat(fixtureJson.substring(fixtureJson.indexOf("\"keypair\""), fixtureJson.indexOf("}", fixtureJson.indexOf("\"keypair\"")) + 1));
        check(Arrays.equals(Arrays.copyOf(pub, 64), b64(gkp.get("public_b64"))), "GOST half of the hybrid public key = plain GOST fixture point");
        String[] mine = VaultClient.generateGostPqcKeyPair();
        check(b64(mine[0]).length == 96 && b64(mine[1]).length == 1248 && VaultClient.gostPqcPublicFromPrivate(mine[0]).equals(mine[1]), "a generated GOST hybrid pair round-trips (any JDK)");
        try { VaultClient.gostPqcPublicFromPrivate(VaultClient.generateGostKeyPair()[0]); check(false, "32-byte key must be refused"); }
        catch (IOException e) { check(e.getMessage().contains("96 bytes"), "gostPqcPublicFromPrivate shape message: " + e.getMessage()); }
        Map<String, String> env0 = envelopes.get(0).sealed;
        check(VaultClient.SEALED_ALG_GOST_PQC.equals(env0.get("alg")) && b64(env0.get("kem")).length == 1088 && b64(env0.get("epk")).length == 64 && b64(env0.get("ukm")).length == 8 && b64(env0.get("nonce")).length == 16, "fixture envelope shape");
        if (!MlKem.available()) {
            try { VaultClient.unseal(env0, kp.get("private_b64"), envelopes.get(0).name); check(false, "unseal must fail without ML-KEM"); }
            catch (IOException e) { check(e.getMessage().contains("Java 24+") && e.getMessage().contains("ML-KEM"), "no-ML-KEM gost-pqc unseal message: " + e.getMessage()); }
            System.out.println("gost-pqc: key generation and public-from-private ok; " + PQC_SKIP);
            return;
        }
        for (PqcEnvelope e : envelopes) {
            Map<String, String> payload = VaultClient.unseal(e.sealed, kp.get("private_b64"), e.name);
            check(payload.size() == e.payload.size(), "gost-pqc payload keys for " + e.name);
            for (Map.Entry<String, String> kv : e.payload.entrySet())
                check(kv.getValue().equals(payload.get(kv.getKey())), e.name + " payload." + kv.getKey() + " = " + payload.get(kv.getKey()));
        }
        check("pg-pass-2026".equals(VaultClient.unseal(env0, kp.get("private_b64"), "core-db").get("value")), "gost-pqc first envelope value");
        for (String field : new String[]{"kem", "epk", "ukm", "ct", "nonce"}) {
            Map<String, String> broken = new HashMap<>(env0);
            byte[] b = b64(env0.get(field)); b[b.length / 2] ^= 1; broken.put(field, b64(b));
            try { VaultClient.unseal(broken, kp.get("private_b64"), "core-db"); check(false, "flipped byte in " + field + " must be refused"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "flipped " + field + " message: " + e.getMessage()); }
        }
        try { VaultClient.unseal(env0, kp.get("private_b64"), "other-secret"); check(false, "wrong name must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "gost-pqc wrong-name message"); }
        try { VaultClient.unseal(env0, mine[0], "core-db"); check(false, "another hybrid key must not open the fixture"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "gost-pqc wrong-key message"); }
        byte[] halfWrong = priv.clone(); halfWrong[40] ^= 1;                                    // right GOST half, wrong seed
        try { VaultClient.unseal(env0, b64(halfWrong), "core-db"); check(false, "wrong ML-KEM half must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "gost-pqc wrong-seed message"); }
        halfWrong = priv.clone(); halfWrong[3] ^= 1;                                            // wrong GOST half, right seed
        try { VaultClient.unseal(env0, b64(halfWrong), "core-db"); check(false, "wrong GOST half must be refused"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "gost-pqc wrong-scalar message"); }
        try { VaultClient.unseal(env0, gkp.get("private_b64"), "core-db"); check(false, "a plain 32-byte GOST key must be refused"); }
        catch (IOException e) { check(e.getMessage().contains("96 bytes"), "gost-pqc with a 32-byte key: " + e.getMessage()); }
        System.out.println("gost-pqc: fixture envelopes open, negatives refused");
    }

    /** Which fixture envelope the fake vault serves for "core-db" on the next request (all are sealed for that name). */
    static final java.util.concurrent.atomic.AtomicReference<String> ENVELOPE = new java.util.concurrent.atomic.AtomicReference<>("x25519");
    static String env(String variant) { ENVELOPE.set(variant); return "core-db"; }

    public static void main(String[] args) throws Exception {
        parseFlatSmallStack();
        // GOST primitives and the server-produced fixture envelope (clients/fixtures/gost-sealed.json)
        fixtureJson = Files.readString(Path.of("../fixtures/gost-sealed.json"), StandardCharsets.UTF_8);
        int si = fixtureJson.indexOf("\"sealed\"");
        gostSealedJson = fixtureJson.substring(si, fixtureJson.indexOf("}", si) + 1);
        long tInit = System.nanoTime();
        Gost.streebog256(new byte[0]);                                   // forces class init (Kuznyechik LS tables)
        System.out.println("gost: class init " + (System.nanoTime() - tInit) / 1_000_000.0 + " ms");
        gostTests();

        // P-256 primitives and the server-produced fixture envelope (clients/fixtures/p256-sealed.json)
        p256Json = Files.readString(Path.of("../fixtures/p256-sealed.json"), StandardCharsets.UTF_8);
        int pi = p256Json.indexOf("\"sealed\"");
        p256SealedJson = p256Json.substring(pi, p256Json.indexOf("}", pi) + 1);
        p256Tests();

        // post-quantum hybrid (clients/fixtures/pqc-sealed.json): KeyGen from the seed on any JDK, the rest with ML-KEM (JDK 24+)
        pqcJson = Files.readString(Path.of("../fixtures/pqc-sealed.json"), StandardCharsets.UTF_8);
        int qi = pqcJson.indexOf("\"sealed\"");
        pqcSealedJson = pqcJson.substring(qi, pqcJson.indexOf("}", qi) + 1);
        pqcTests();

        // GOST post-quantum hybrid (clients/fixtures/gost-pqc-sealed.json)
        gostPqcJson = Files.readString(Path.of("../fixtures/gost-pqc-sealed.json"), StandardCharsets.UTF_8);
        gostPqcTests();

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
                // every envelope below was sealed by the server (backend/sealed.py) for the secret NAMED core-db, so the
                // test picks which one is served through ENVELOPE (consumed per request; default: X25519)
                String v = ENVELOPE.getAndSet("x25519");
                String sealedPart;
                switch (v) {
                    case "gost": sealedPart = gostSealedJson; break;
                    case "p256": sealedPart = p256SealedJson; break;
                    case "pqc": sealedPart = pqcSealedJson; break;
                    default: sealedPart = "\"sealed\":{\"alg\":\"X25519-HKDF-SHA256-AES256GCM\",\"v\":1,\"epk\":\"qId7VmcoFhnApxHZznkoaKFl/wIl/z2HauZI+GMVI1Q=\",\"nonce\":\"qTsci1J2iUT0nr58\",\"ct\":\"DmXYnxSzPc9d6MIdODi2I9bd2nw4yi3mBUWcxVHLDVlX/ax+BH5DcqBh2PBcBt8E7eTZouxd0SyW+fzJ4dlXL+F4SL2HrSY=\"}";
                }
                reply(ex, 200, "{\"name\":\"core-db\",\"version\":1,\"current_version\":1,\"updated_at\":\"x\"," + sealedPart + "}");
            } else if (m.equals("GET") && p.equals("/api/v1/m/secret/swapped")) {
                // 0.37: a tampering proxy answers a request for "swapped" with core-db's envelope and core-db's name
                reply(ex, 200, "{\"name\":\"core-db\",\"version\":1,\"current_version\":1,\"updated_at\":\"x\",\"sealed\":{\"alg\":\"X25519-HKDF-SHA256-AES256GCM\",\"v\":1,\"epk\":\"qId7VmcoFhnApxHZznkoaKFl/wIl/z2HauZI+GMVI1Q=\",\"nonce\":\"qTsci1J2iUT0nr58\",\"ct\":\"DmXYnxSzPc9d6MIdODi2I9bd2nw4yi3mBUWcxVHLDVlX/ax+BH5DcqBh2PBcBt8E7eTZouxd0SyW+fzJ4dlXL+F4SL2HrSY=\"}}");
            } else if (m.equals("GET") && p.equals("/api/v1/m/secret/hw-secret") && hwSealedJson != null) {
                // sealed in the test to the hardware token's point
                reply(ex, 200, "{\"name\":\"hw-secret\",\"version\":1,\"current_version\":1,\"updated_at\":\"x\"," + hwSealedJson + "}");
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
            // 0.37: the AAD is the REQUESTED name — another secret's envelope (with its own name in the body) does not open
            try { sealed.get("swapped"); check(false, "a swapped envelope must not open"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "swapped-envelope message: " + e.getMessage()); }
            // 0.37: with a key configured, a plaintext answer is refused (a proxy could have dropped the envelope)
            try { sealed.get("db-password"); check(false, "a plaintext answer must be refused when a client key is configured"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("not sealed"), "plaintext-refused message: " + e.getMessage()); }
            String[] kp = VaultClient.generateKeyPair();
            check(java.util.Base64.getDecoder().decode(kp[0]).length == 32 && java.util.Base64.getDecoder().decode(kp[1]).length == 32, "key pair is raw 32 bytes each");

            // GOST sealed delivery through the client: same key, the envelope's alg selects the GOST path
            VaultClient.Secret gs = sealed.getFull(env("gost"));
            check("pg-pass-2026".equals(gs.value) && "core".equals(gs.login) && "123456".equals(gs.totp), "gost sealed payload: " + gs.value + "/" + gs.login + "/" + gs.totp);
            check("core-db".equals(gs.name), "gost sealed name kept");
            check("123456".equals(sealed.totp(env("gost")).orElse(null)), "gost sealed totp");
            VaultClient wrongGost = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, VaultClient.generateGostKeyPair()[0]);
            try { wrongGost.get(env("gost")); check(false, "another GOST key must not open the envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "gost wrong-key message: " + e.getMessage()); }
            try { wrongGost.get("core-db"); check(false, "a GOST key must not open the X25519 envelope"); }
            catch (IOException expected) { }
            try { noKey.get(env("gost")); check(false, "without a key the client must refuse the GOST envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("sealed values"), "gost no-key message"); }
            String[] gkp = VaultClient.generateGostKeyPair();
            check(java.util.Base64.getDecoder().decode(gkp[0]).length == 32 && java.util.Base64.getDecoder().decode(gkp[1]).length == 64, "GOST key pair is 32 + 64 raw bytes");

            // P-256 sealed delivery through the client: the fixture envelope opens with scalar‖point, and only with it
            Map<String, String> pkp = p256Section("keypair");
            byte[] p256Priv = Arrays.copyOf(b64(pkp.get("private_b64")), 97); System.arraycopy(b64(pkp.get("public_b64")), 0, p256Priv, 32, 65);
            VaultClient sealedP256 = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, b64(p256Priv));
            VaultClient.Secret ps = sealedP256.getFull(env("p256"));
            check("pg-pass-2026".equals(ps.value) && "core".equals(ps.login) && "123456".equals(ps.totp), "p256 sealed payload: " + ps.value + "/" + ps.login + "/" + ps.totp);
            check("core-db".equals(ps.name), "p256 sealed name kept");
            check("123456".equals(sealedP256.totp(env("p256")).orElse(null)), "p256 sealed totp");
            VaultClient wrongP256 = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, VaultClient.generateP256KeyPair()[0]);
            try { wrongP256.get(env("p256")); check(false, "another P-256 key must not open the envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "p256 wrong-key message: " + e.getMessage()); }
            try { wrongP256.get("core-db"); check(false, "a P-256 key must not open the X25519 envelope"); }
            catch (IOException expected) { }
            try { sealed.get(env("p256")); check(false, "the bare 32-byte X25519 key must be refused for the P-256 envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("97 bytes"), "p256 bare-scalar message via client: " + e.getMessage()); }
            try { noKey.get(env("p256")); check(false, "without a key the client must refuse the P-256 envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("sealed values"), "p256 no-key message"); }

            // post-quantum hybrid delivery through the client: the fixture envelope opens with the 96-byte key, and only with it
            Map<String, String> qkp = pqcSection("keypair");
            VaultClient sealedPqc = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, qkp.get("private_b64"));
            try { sealed.get(env("pqc")); check(false, "the bare 32-byte X25519 key must be refused for the hybrid envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("96 bytes"), "pqc 32-byte key message via client: " + e.getMessage()); }
            try { noKey.get(env("pqc")); check(false, "without a key the client must refuse the hybrid envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("sealed values"), "pqc no-key message"); }
            try { sealedPqc.get("core-db"); check(false, "a hybrid key must not open the X25519 envelope"); }
            catch (IOException expected) { }
            if (MlKem.available()) {
                VaultClient.Secret qs = sealedPqc.getFull(env("pqc"));
                check("pg-pass-2026".equals(qs.value) && "core".equals(qs.login) && "hybrid fixture".equals(qs.notes), "pqc sealed payload: " + qs.value + "/" + qs.login + "/" + qs.notes);
                check("core-db".equals(qs.name) && qs.totp == null, "pqc sealed name kept, no totp in this fixture");
                VaultClient wrongPqc = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, VaultClient.generatePqcKeyPair()[0]);
                try { wrongPqc.get(env("pqc")); check(false, "another hybrid key must not open the envelope"); }
                catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "pqc wrong-key message: " + e.getMessage()); }
                String[] eq = VaultClient.enroll(base, "enr_ok", "host-1", "pqc");
                check("vlt_enrolled".equals(eq[0]) && b64(eq[1]).length == 96 && b64(eq[2]).length == 1216 && "node-host-1".equals(eq[3]), "pqc enrol: 96-byte private, 1216-byte public");
                check(VaultClient.pqcPublicFromPrivate(eq[1]).equals(eq[2]), "pqc enrol public == derived from private");
            } else {
                try { sealedPqc.get(env("pqc")); check(false, "the hybrid envelope must fail clearly without ML-KEM"); }
                catch (IOException e) { check(e.getMessage().contains("Java 24+"), "pqc client no-ML-KEM message: " + e.getMessage()); }
                try { VaultClient.enroll(base, "enr_ok", "host-1", "pqc"); check(false, "pqc enrol must fail clearly without ML-KEM"); }
                catch (IOException e) { check(e.getMessage().contains("Java 24+"), "pqc enrol no-ML-KEM message: " + e.getMessage()); }
            }

            // enrolment: local key pair, token sealed to it; a bad code is a 404
            String[] en = VaultClient.enroll(base, "enr_ok", "host-1", false);
            check("vlt_enrolled".equals(en[0]) && java.util.Base64.getDecoder().decode(en[1]).length == 32 && "node-host-1".equals(en[3]), "enrol result");
            String[] eg = VaultClient.enroll(base, "enr_ok", "host-1", true);
            check(java.util.Base64.getDecoder().decode(eg[2]).length == 64, "gost enrol public key is 64 bytes");
            try { VaultClient.enroll(base, "enr_bad", "host-1", false); check(false, "bad code must fail"); }
            catch (VaultClient.VaultException e) { check(e.status == 404, "enrol 404"); }
            String[] ep = VaultClient.enroll(base, "enr_ok", "host-1", "p256");
            check("vlt_enrolled".equals(ep[0]) && java.util.Base64.getDecoder().decode(ep[1]).length == 97 && java.util.Base64.getDecoder().decode(ep[2]).length == 65, "p256 enrol: 97-byte private, 65-byte point");
            try { VaultClient.enroll(base, "enr_ok", "host-1", "rsa"); check(false, "unknown key kind must fail"); }
            catch (IllegalArgumentException expected) { }
            // hardware-style enrolment with a software EC key standing in for the token: only the point is sent
            KeyPairGenerator ecg = KeyPairGenerator.getInstance("EC"); ecg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair swEc = ecg.generateKeyPair();
            byte[] swPoint = VaultClient.encodePoint(((ECPublicKey) swEc.getPublic()).getW());
            String[] eh = VaultClient.enroll(base, "enr_ok", "host-1", swEc.getPrivate(), swPoint);
            check("vlt_enrolled".equals(eh[0]) && "".equals(eh[1]) && b64(swPoint).equals(eh[2]) && "node-host-1".equals(eh[3]) && "f".equals(eh[4]), "hardware-style enrol result");
            try { VaultClient.enroll(base, "enr_ok", "host-1", swEc.getPrivate(), new byte[32]); check(false, "32-byte point must be refused"); }
            catch (IllegalArgumentException expected) { }
            // withKeyProvider with a software EC PrivateKey behaves like the hardware path (JCA picks SunEC for it)
            Map<String, String> swEnv = sealP256(swPoint, "hw-secret", "{\"value\":\"soft-hw\"}");
            hwSealedJson = sealedJson(swEnv);
            VaultClient viaProvider = noKey.withKeyProvider(swEc.getPrivate(), swPoint);
            check("soft-hw".equals(viaProvider.get("hw-secret")), "withKeyProvider with a software EC key");
            try { viaProvider.get("core-db"); check(false, "key provider must refuse the X25519 envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("opens only the P-256 envelope, the token sent X25519-HKDF-SHA256-AES256GCM"), "provider non-P256 message: " + e.getMessage()); }
            hwSealedJson = null;

            v.put("new", "v", "u", "", "");
            check(v.health().contains("\"status\":\"ok\""), "health");

            // 401
            VaultClient bad = new VaultClient(base, "vlt_wrong");
            try { bad.get("db-password"); check(false, "401 expected"); }
            catch (VaultClient.VaultException e) { check(e.status == 401, "status 401"); }

            // flat JSON parser corner cases
            var m = VaultClient.parseFlat("{\"a\":\"x\\u0041\\n\",\"n\":12,\"t\":true,\"z\":null}");
            check("xA\n".equals(m.get("a")) && "12".equals(m.get("n")) && "true".equals(m.get("t")) && m.containsKey("z") && m.get("z") == null, "parseFlat");

            // the hardware key (SoftHSM2 through SunPKCS11) — skipped with a message when the token is not configured
            hardwareTests(base, VaultClient.parseFlat(p256SealedJson));
            System.out.println("VaultClientTest: OK");
        } finally {
            srv.stop(0);
        }
    }
}
