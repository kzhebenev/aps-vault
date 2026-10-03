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
        try { hw.get("core-db-gost"); check(false, "a hardware key must refuse the GOST envelope"); }
        catch (VaultClient.VaultException e) { check(e.getMessage().contains("opens only the P-256 envelope"), "hw gost message"); }
        try { hw.get("core-db-p256"); check(false, "the fixture envelope is bound to the software key, not the token"); }
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

        // P-256 primitives and the server-produced fixture envelope (clients/fixtures/p256-sealed.json)
        p256Json = Files.readString(Path.of("../fixtures/p256-sealed.json"), StandardCharsets.UTF_8);
        int pi = p256Json.indexOf("\"sealed\"");
        p256SealedJson = p256Json.substring(pi, p256Json.indexOf("}", pi) + 1);
        p256Tests();

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
            } else if (m.equals("GET") && p.equals("/api/v1/m/secret/core-db-p256")) {
                // the P-256 envelope from the fixture file, sealed by the server for the scalar 0x01..0x20
                reply(ex, 200, "{\"name\":\"core-db\",\"version\":1,\"current_version\":1,\"updated_at\":\"x\"," + p256SealedJson + "}");
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

            // P-256 sealed delivery through the client: the fixture envelope opens with scalar‖point, and only with it
            Map<String, String> pkp = p256Section("keypair");
            byte[] p256Priv = Arrays.copyOf(b64(pkp.get("private_b64")), 97); System.arraycopy(b64(pkp.get("public_b64")), 0, p256Priv, 32, 65);
            VaultClient sealedP256 = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, b64(p256Priv));
            VaultClient.Secret ps = sealedP256.getFull("core-db-p256");
            check("pg-pass-2026".equals(ps.value) && "core".equals(ps.login) && "123456".equals(ps.totp), "p256 sealed payload: " + ps.value + "/" + ps.login + "/" + ps.totp);
            check("core-db".equals(ps.name), "p256 sealed name kept");
            check("123456".equals(sealedP256.totp("core-db-p256").orElse(null)), "p256 sealed totp");
            VaultClient wrongP256 = new VaultClient(base, "vlt_test_token", Duration.ZERO, Duration.ofSeconds(2), 1, true, VaultClient.generateP256KeyPair()[0]);
            try { wrongP256.get("core-db-p256"); check(false, "another P-256 key must not open the envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("does not open"), "p256 wrong-key message: " + e.getMessage()); }
            try { wrongP256.get("core-db"); check(false, "a P-256 key must not open the X25519 envelope"); }
            catch (IOException expected) { }
            try { sealed.get("core-db-p256"); check(false, "the bare 32-byte X25519 key must be refused for the P-256 envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("97 bytes"), "p256 bare-scalar message via client: " + e.getMessage()); }
            try { noKey.get("core-db-p256"); check(false, "without a key the client must refuse the P-256 envelope"); }
            catch (VaultClient.VaultException e) { check(e.getMessage().contains("sealed values"), "p256 no-key message"); }

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
