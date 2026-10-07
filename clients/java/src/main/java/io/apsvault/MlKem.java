package io.apsvault;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.SecretKey;

/**
 * ML-KEM-768 (FIPS 203) glue for the hybrid envelope {@link VaultClient#SEALED_ALG_PQC} (0.27).
 *
 * Two halves live here:
 * <ul>
 *   <li>Encapsulation / decapsulation go through the JDK's {@code javax.crypto.KEM} ("ML-KEM", JDK 24+). The class
 *       is reached by reflection so this client still compiles and runs on Java 11–23, where the hybrid envelope
 *       is simply unavailable (every entry point then throws with {@link #NEEDS_JAVA}). The JDK encodes an ML-KEM
 *       private key in the FIPS 203 seed form (PKCS#8 of 86 bytes = {@link #PKCS8_PREFIX} ‖ d‖z), so the 64-byte
 *       seed the vault's key format carries is imported directly; the public key is an SPKI of 1206 bytes =
 *       {@link #SPKI_PREFIX} ‖ the 1184-byte encapsulation key.</li>
 *   <li>Deriving the encapsulation key from the seed ({@link #publicFromSeed(byte[])}). The JDK offers no supported
 *       way to do that (the private key object knows how, but it lives in a non-exported package), so ML-KEM.KeyGen
 *       (FIPS 203 Algorithms 13/16, the public half only) is implemented here in plain Java with its own Keccak:
 *       SHA3-512 for G, SHAKE128 for the matrix A, SHAKE256 for the CBD noise, the 7-layer NTT and ByteEncode12.
 *       It runs on any Java version and is cross-checked against the JDK's own encapsulation key in
 *       {@link #generate()}.</li>
 * </ul>
 */
final class MlKem {
    private MlKem() { }

    static final int Q = 3329, K = 3, ETA1 = 2;
    static final int SEED_LEN = 64, EK_LEN = 1184, CT_LEN = 1088, SS_LEN = 32;
    static final String NEEDS_JAVA = "the post-quantum envelope needs Java 24+ (ML-KEM)";
    /** PKCS#8 of a seed-form ML-KEM-768 private key: OneAsymmetricKey v1, id-alg-ml-kem-768, OCTET STRING { seed [0] (64 bytes) }. */
    static final byte[] PKCS8_PREFIX = hex("3054020100300b060960864801650304040204428040");
    /** SubjectPublicKeyInfo of an ML-KEM-768 public key: id-alg-ml-kem-768, BIT STRING of the 1184-byte encapsulation key. */
    static final byte[] SPKI_PREFIX = hex("308204b2300b0609608648016503040402038204a100");

    // ── JDK KEM through reflection ──────────────────────────────────────────
    /** True when this JDK has ML-KEM-768 and {@code javax.crypto.KEM} (JDK 24+). */
    static boolean available() {
        try { KeyPairGenerator.getInstance("ML-KEM-768"); Class.forName("javax.crypto.KEM"); return true; }
        catch (NoSuchAlgorithmException | ClassNotFoundException e) { return false; }
    }

    /** The JDK private key for a 64-byte seed d‖z (seed-form PKCS#8). */
    static PrivateKey privateFromSeed(byte[] seed) throws GeneralSecurityException {
        if (seed.length != SEED_LEN) throw new IllegalArgumentException("ML-KEM-768 seed must be 64 bytes, got " + seed.length);
        return keyFactory().generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, seed)));
    }

    /** The JDK public key for a 1184-byte encapsulation key. */
    static PublicKey publicFromEk(byte[] ek) throws GeneralSecurityException {
        if (ek.length != EK_LEN) throw new IllegalArgumentException("ML-KEM-768 encapsulation key must be 1184 bytes, got " + ek.length);
        return keyFactory().generatePublic(new X509EncodedKeySpec(concat(SPKI_PREFIX, ek)));
    }

    private static KeyFactory keyFactory() throws GeneralSecurityException {
        try { return KeyFactory.getInstance("ML-KEM-768"); }
        catch (NoSuchAlgorithmException e) { throw new NoSuchAlgorithmException(NEEDS_JAVA, e); }
    }

    private static Object kem() throws GeneralSecurityException {
        try {
            Class<?> c = Class.forName("javax.crypto.KEM");
            return c.getMethod("getInstance", String.class).invoke(null, "ML-KEM");
        } catch (ClassNotFoundException e) {
            throw new NoSuchAlgorithmException(NEEDS_JAVA, e);
        } catch (ReflectiveOperationException e) {
            throw unwrap(e);
        }
    }

    /** ML-KEM.Decaps: the 32-byte shared secret for a 1088-byte ciphertext. A foreign or damaged ciphertext yields a
     *  different secret (implicit rejection), not an exception — the AES-GCM tag catches that. */
    static byte[] decapsulate(PrivateKey dk, byte[] ct) throws GeneralSecurityException {
        if (ct.length != CT_LEN) throw new IllegalArgumentException("ML-KEM-768 ciphertext must be 1088 bytes, got " + ct.length);
        try {
            Object kem = kem();
            Object dec = kem.getClass().getMethod("newDecapsulator", PrivateKey.class).invoke(kem, dk);
            Method m = dec.getClass().getMethod("decapsulate", byte[].class);
            return ((SecretKey) m.invoke(dec, (Object) ct)).getEncoded();
        } catch (ReflectiveOperationException e) {
            throw unwrap(e);
        }
    }

    /** ML-KEM.Encaps to {@code ek}: {ciphertext (1088), shared secret (32)}. Used by the test-side sealer and the
     *  self-check in {@link #generate()}; the vault does this on its side when it seals. */
    static byte[][] encapsulate(PublicKey ek) throws GeneralSecurityException {
        try {
            Object kem = kem();
            Object enc = kem.getClass().getMethod("newEncapsulator", PublicKey.class).invoke(kem, ek);
            Object encd = enc.getClass().getMethod("encapsulate").invoke(enc);
            byte[] ct = (byte[]) encd.getClass().getMethod("encapsulation").invoke(encd);
            byte[] ss = ((SecretKey) encd.getClass().getMethod("key").invoke(encd)).getEncoded();
            return new byte[][]{ct, ss};
        } catch (ReflectiveOperationException e) {
            throw unwrap(e);
        }
    }

    private static GeneralSecurityException unwrap(ReflectiveOperationException e) {
        Throwable c = e instanceof InvocationTargetException ? e.getCause() : e;
        if (c instanceof GeneralSecurityException) return (GeneralSecurityException) c;
        if (c instanceof RuntimeException) throw (RuntimeException) c;
        return new GeneralSecurityException("ML-KEM: " + c, c);
    }

    /** A fresh pair from the JDK: {seed d‖z (64), encapsulation key (1184)}. The seed is cut out of the seed-form
     *  PKCS#8 and the derivation in {@link #publicFromSeed(byte[])} is checked against the JDK's public key, so a
     *  JDK that encoded its private key differently is caught here rather than when the vault seals to a key
     *  that the seed cannot reproduce. */
    static byte[][] generate() throws GeneralSecurityException {
        KeyPairGenerator g;
        try { g = KeyPairGenerator.getInstance("ML-KEM-768"); }
        catch (NoSuchAlgorithmException e) { throw new NoSuchAlgorithmException(NEEDS_JAVA, e); }
        KeyPair kp = g.generateKeyPair();
        byte[] sk = kp.getPrivate().getEncoded(), pk = kp.getPublic().getEncoded();
        if (sk == null || sk.length != PKCS8_PREFIX.length + SEED_LEN || !Arrays.equals(Arrays.copyOf(sk, PKCS8_PREFIX.length), PKCS8_PREFIX))
            throw new GeneralSecurityException("this JDK does not encode ML-KEM-768 private keys in the FIPS 203 seed form (" + (sk == null ? "null" : sk.length + " bytes") + ")");
        if (pk == null || pk.length != SPKI_PREFIX.length + EK_LEN || !Arrays.equals(Arrays.copyOf(pk, SPKI_PREFIX.length), SPKI_PREFIX))
            throw new GeneralSecurityException("unexpected ML-KEM-768 public key encoding (" + (pk == null ? "null" : pk.length + " bytes") + ")");
        byte[] seed = Arrays.copyOfRange(sk, PKCS8_PREFIX.length, sk.length), ek = Arrays.copyOfRange(pk, SPKI_PREFIX.length, pk.length);
        if (!Arrays.equals(publicFromSeed(seed), ek))
            throw new GeneralSecurityException("ML-KEM-768 key derivation disagrees with the JDK's encapsulation key");
        return new byte[][]{seed, ek};
    }

    // ── ML-KEM.KeyGen, public half (FIPS 203 Algorithms 13 and 16), plain Java ─────────────────────────────────────
    private static final int[] ZETAS = new int[128];     // 17^BitRev7(i) mod q
    private static final int[] GAMMAS = new int[128];    // 17^(2·BitRev7(i)+1) mod q
    static {
        for (int i = 0; i < 128; i++) {
            int r = Integer.reverse(i) >>> 25;           // BitRev7
            ZETAS[i] = pow17(r);
            GAMMAS[i] = pow17(2 * r + 1);
        }
    }
    private static int pow17(int e) { int r = 1, b = 17; while (e > 0) { if ((e & 1) != 0) r = r * b % Q; b = b * b % Q; e >>= 1; } return r; }

    /** The 1184-byte encapsulation key that belongs to the 64-byte seed d‖z. */
    static byte[] publicFromSeed(byte[] seed) {
        if (seed.length != SEED_LEN) throw new IllegalArgumentException("ML-KEM-768 seed must be 64 bytes, got " + seed.length);
        byte[] rs;
        try {
            MessageDigest g = MessageDigest.getInstance("SHA3-512");         // G(d ‖ k)
            g.update(seed, 0, 32); g.update((byte) K);
            rs = g.digest();
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA3-512 missing", e); }
        byte[] rho = Arrays.copyOf(rs, 32), sigma = Arrays.copyOfRange(rs, 32, 64);
        int[][][] a = new int[K][K][];
        for (int i = 0; i < K; i++) for (int j = 0; j < K; j++) a[i][j] = sampleNtt(rho, j, i);
        int n = 0;
        int[][] s = new int[K][], e = new int[K][];
        for (int i = 0; i < K; i++) s[i] = ntt(cbd(prf(sigma, n++)));
        for (int i = 0; i < K; i++) e[i] = ntt(cbd(prf(sigma, n++)));
        byte[] ek = new byte[EK_LEN];
        for (int i = 0; i < K; i++) {
            int[] t = e[i].clone();
            for (int j = 0; j < K; j++) { int[] p = mulNtt(a[i][j], s[j]); for (int c = 0; c < 256; c++) t[c] = (t[c] + p[c]) % Q; }
            encode12(t, ek, i * 384);
        }
        System.arraycopy(rho, 0, ek, K * 384, 32);
        return ek;
    }

    /** Algorithm 7 SampleNTT: rejection-sample a polynomial in the NTT domain from SHAKE128(ρ ‖ j ‖ i). */
    private static int[] sampleNtt(byte[] rho, int j, int i) {
        Shake x = new Shake(128);
        x.absorb(rho); x.absorb(new byte[]{(byte) j, (byte) i});
        int[] out = new int[256];
        int k = 0;
        while (k < 256) {
            byte[] c = x.squeeze(3);
            int d1 = (c[0] & 0xff) | ((c[1] & 0x0f) << 8), d2 = ((c[1] & 0xff) >> 4) | ((c[2] & 0xff) << 4);
            if (d1 < Q) out[k++] = d1;
            if (d2 < Q && k < 256) out[k++] = d2;
        }
        return out;
    }

    /** PRF_η(σ, N) = SHAKE256(σ ‖ N, 64·η bytes). */
    private static byte[] prf(byte[] sigma, int nonce) {
        Shake x = new Shake(256);
        x.absorb(sigma); x.absorb(new byte[]{(byte) nonce});
        return x.squeeze(64 * ETA1);
    }

    /** Algorithm 8 SamplePolyCBD with η = 2. */
    private static int[] cbd(byte[] b) {
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) {
            int x = bit(b, 4 * i) + bit(b, 4 * i + 1), y = bit(b, 4 * i + 2) + bit(b, 4 * i + 3);
            f[i] = (x - y + Q) % Q;
        }
        return f;
    }
    private static int bit(byte[] b, int k) { return (b[k >> 3] >> (k & 7)) & 1; }

    /** Algorithm 9 NTT. */
    private static int[] ntt(int[] f) {
        int[] a = f.clone();
        int i = 1;
        for (int len = 128; len >= 2; len >>= 1)
            for (int start = 0; start < 256; start += 2 * len) {
                int z = ZETAS[i++];
                for (int j = start; j < start + len; j++) {
                    int t = z * a[j + len] % Q;
                    a[j + len] = (a[j] - t + Q) % Q;
                    a[j] = (a[j] + t) % Q;
                }
            }
        return a;
    }

    /** Algorithms 11/12 MultiplyNTTs with BaseCaseMultiply. */
    private static int[] mulNtt(int[] f, int[] g) {
        int[] h = new int[256];
        for (int i = 0; i < 128; i++) {
            int a0 = f[2 * i], a1 = f[2 * i + 1], b0 = g[2 * i], b1 = g[2 * i + 1];
            h[2 * i] = (a0 * b0 + a1 * b1 % Q * GAMMAS[i]) % Q;
            h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q;
        }
        return h;
    }

    /** Algorithm 5 ByteEncode12: 256 coefficients → 384 bytes, little-endian bit packing. */
    private static void encode12(int[] t, byte[] out, int off) {
        for (int i = 0; i < 128; i++) {
            int a0 = t[2 * i], a1 = t[2 * i + 1];
            out[off + 3 * i] = (byte) a0;
            out[off + 3 * i + 1] = (byte) ((a0 >> 8) | (a1 << 4));
            out[off + 3 * i + 2] = (byte) (a1 >> 4);
        }
    }

    // ── Keccak sponge (SHAKE128 / SHAKE256, FIPS 202) ───────────────────────
    /** A SHAKE XOF: absorb any number of times, then squeeze any number of times. */
    static final class Shake {
        private final long[] st = new long[25];
        private final int rate;
        private int pos = 0;
        private boolean squeezing = false;

        /** {@code bits} = 128 or 256. */
        Shake(int bits) { rate = 200 - bits / 4; }

        void absorb(byte[] in) {
            if (squeezing) throw new IllegalStateException("absorb after squeeze");
            for (byte b : in) {
                st[pos >> 3] ^= (long) (b & 0xff) << (8 * (pos & 7));
                if (++pos == rate) { keccakF(st); pos = 0; }
            }
        }

        byte[] squeeze(int n) {
            if (!squeezing) {                                             // pad10*1 with the SHAKE domain bits 1111
                st[pos >> 3] ^= 0x1FL << (8 * (pos & 7));
                st[(rate - 1) >> 3] ^= 0x80L << (8 * ((rate - 1) & 7));
                keccakF(st); pos = 0; squeezing = true;
            }
            byte[] out = new byte[n];
            for (int i = 0; i < n; i++) {
                if (pos == rate) { keccakF(st); pos = 0; }
                out[i] = (byte) (st[pos >> 3] >>> (8 * (pos & 7)));
                pos++;
            }
            return out;
        }
    }

    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
    private static final int[] ROTC = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
    private static final int[] PILN = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

    /** Keccak-f[1600] on 25 little-endian lanes. */
    static void keccakF(long[] s) {
        long[] bc = new long[5];
        for (int round = 0; round < 24; round++) {
            for (int i = 0; i < 5; i++) bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
            for (int i = 0; i < 5; i++) {
                long t = bc[(i + 4) % 5] ^ Long.rotateLeft(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) s[j + i] ^= t;
            }
            long t = s[1];
            for (int i = 0; i < 24; i++) { int j = PILN[i]; long tmp = s[j]; s[j] = Long.rotateLeft(t, ROTC[i]); t = tmp; }
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) bc[i] = s[j + i];
                for (int i = 0; i < 5; i++) s[j + i] ^= ~bc[(i + 1) % 5] & bc[(i + 2) % 5];
            }
            s[0] ^= RC[round];
        }
    }

    static byte[] concat(byte[] a, byte[] b) { byte[] r = Arrays.copyOf(a, a.length + b.length); System.arraycopy(b, 0, r, a.length, b.length); return r; }
    private static byte[] hex(String h) { byte[] r = new byte[h.length() / 2]; for (int i = 0; i < r.length; i++) r[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16); return r; }
}
