package io.apsvault;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * GOST primitives for the sealed-delivery envelope {@code VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM}
 * (see {@code clients/GOST-PORTING.md}): Streebog (GOST R 34.11-2012), HMAC-Streebog-256 and
 * KDF_TREE_GOSTR3411_2012_256 (R 50.1.113), Kuznyechik (GOST R 34.12-2015), MGM (RFC 9058), the
 * 256-bit curve {@code id-tc26-gost-3410-2012-256-paramSetB} with VKO (RFC 7836 §4.3).
 *
 * Pure Java 11, no dependencies; constant tables come from the generated {@link GostConsts}.
 * Algorithm-level conformance checked against the published test vectors — not a certified СКЗИ.
 * The scalar multiplication is not constant-time (same model as the X25519 envelope: the client's
 * private key runs on the client's own machine, the vault's ephemeral scalars are single-use).
 */
public final class Gost {
    private Gost() {}

    static final String LABEL = "aps-vault/sealed-gost/v1";

    // ── Streebog — GOST R 34.11-2012 ────────────────────────────────────────
    private static final long[][] T = GostConsts.STREEBOG_T;
    private static final byte[][] C = GostConsts.STREEBOG_C;

    private static byte[] xor64(byte[] a, byte[] b) {
        byte[] r = new byte[64];
        for (int i = 0; i < 64; i++) r[i] = (byte) (a[i] ^ b[i]);
        return r;
    }

    /** LPS: output word i (bytes 8i..8i+7, little-endian) = XOR_j T[j][x[i + 8j]]. */
    private static byte[] lps(byte[] x) {
        byte[] out = new byte[64];
        for (int i = 0; i < 8; i++) {
            long v = 0;
            for (int j = 0; j < 8; j++) v ^= T[j][x[i + 8 * j] & 0xff];
            for (int k = 0; k < 8; k++) out[8 * i + k] = (byte) (v >>> (8 * k));
        }
        return out;
    }

    private static byte[] e(byte[] k, byte[] m) {
        byte[] s = xor64(k, m);
        for (int i = 0; i < 12; i++) {
            s = lps(s);
            k = lps(xor64(k, C[i]));
            s = xor64(s, k);
        }
        return s;
    }

    private static byte[] g(byte[] h, byte[] n, byte[] m) {
        return xor64(xor64(e(lps(xor64(h, n)), m), h), m);
    }

    /** a += b as 512-bit little-endian numbers (byte 0 least significant), carry dropped. */
    private static void add512(byte[] a, byte[] b) {
        int c = 0;
        for (int i = 0; i < 64; i++) {
            c = (a[i] & 0xff) + (b[i] & 0xff) + (c >> 8);
            a[i] = (byte) c;
        }
    }

    private static byte[] streebog(byte[] data, boolean is256) {
        byte[] h = new byte[64];
        if (is256) Arrays.fill(h, (byte) 1);
        byte[] n = new byte[64], sigma = new byte[64], v512 = new byte[64];
        v512[1] = 2;
        int off = 0;
        while (data.length - off >= 64) {
            byte[] m = Arrays.copyOfRange(data, off, off + 64);
            h = g(h, n, m);
            add512(n, v512);
            add512(sigma, m);
            off += 64;
        }
        int r = data.length - off;
        byte[] m = new byte[64];
        System.arraycopy(data, off, m, 0, r);
        m[r] = 1;
        h = g(h, n, m);
        byte[] bits = new byte[64];
        bits[0] = (byte) (r * 8);
        bits[1] = (byte) ((r * 8) >> 8);
        add512(n, bits);
        add512(sigma, m);
        h = g(h, new byte[64], n);
        h = g(h, new byte[64], sigma);
        return is256 ? Arrays.copyOfRange(h, 32, 64) : h;
    }

    public static byte[] streebog256(byte[] data) { return streebog(data, true); }

    public static byte[] streebog512(byte[] data) { return streebog(data, false); }

    /** RFC 2104 HMAC over Streebog-256, block size 64 (R 50.1.113); keys longer than 64 bytes are hashed first. */
    public static byte[] hmacStreebog256(byte[] key, byte[] data) {
        if (key.length > 64) key = streebog256(key);
        byte[] k = Arrays.copyOf(key, 64);
        byte[] ipad = new byte[64 + data.length], opad = new byte[64 + 32];
        for (int i = 0; i < 64; i++) { ipad[i] = (byte) (k[i] ^ 0x36); opad[i] = (byte) (k[i] ^ 0x5c); }
        System.arraycopy(data, 0, ipad, 64, data.length);
        System.arraycopy(streebog256(ipad), 0, opad, 64, 32);
        return streebog256(opad);
    }

    /** KDF_TREE_GOSTR3411_2012_256 (R 50.1.113 §4.5), one key: HMAC256(key, 0x01 ‖ label ‖ 0x00 ‖ seed ‖ 0x01 0x00). */
    public static byte[] kdfTree256(byte[] key, byte[] label, byte[] seed) {
        byte[] msg = new byte[1 + label.length + 1 + seed.length + 2];
        msg[0] = 1;
        System.arraycopy(label, 0, msg, 1, label.length);
        msg[1 + label.length] = 0;
        System.arraycopy(seed, 0, msg, 2 + label.length, seed.length);
        msg[msg.length - 2] = 1;
        msg[msg.length - 1] = 0;
        return hmacStreebog256(key, msg);
    }

    // ── Kuznyechik — GOST R 34.12-2015 ──────────────────────────────────────
    // A 128-bit block is a pair of longs (hi = bytes 0..7 big-endian, lo = bytes 8..15).
    private static final int[] PI = GostConsts.KUZNYECHIK_PI;
    private static final int[] PI_INV = new int[256];
    private static final int[] LVEC = {148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1};
    private static final long[][] LS_HI = new long[16][256], LS_LO = new long[16][256];
    private static final long[][] LSI_HI = new long[16][256], LSI_LO = new long[16][256];
    private static final long[] RC_HI = new long[32], RC_LO = new long[32];

    private static int gfMul(int a, int b) {
        int p = 0;
        while (b != 0) {
            if ((b & 1) != 0) p ^= a;
            a <<= 1;
            if ((a & 0x100) != 0) a ^= 0x1C3;
            b >>= 1;
        }
        return p;
    }

    private static int ell(int[] s, int[][] mul) {
        int acc = 0;
        for (int i = 0; i < 16; i++) acc ^= mul[i][s[i]];
        return acc;
    }

    private static void lTransform(int[] s, int[][] mul) {
        for (int r = 0; r < 16; r++) {
            int acc = ell(s, mul);
            System.arraycopy(s, 0, s, 1, 15);
            s[0] = acc;
        }
    }

    private static void lInverse(int[] s, int[][] mul) {
        for (int r = 0; r < 16; r++) {
            int a0 = s[0];
            System.arraycopy(s, 1, s, 0, 15);
            s[15] = 0;
            s[15] = a0 ^ ell(s, mul);
        }
    }

    private static long hiOf(int[] s) { long v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | s[i]; return v; }
    private static long loOf(int[] s) { long v = 0; for (int i = 8; i < 16; i++) v = (v << 8) | s[i]; return v; }

    static {
        for (int i = 0; i < 256; i++) PI_INV[PI[i]] = i;
        int[][] mul = new int[16][256];
        for (int i = 0; i < 16; i++) for (int x = 0; x < 256; x++) mul[i][x] = gfMul(x, LVEC[i]);
        int[] blk = new int[16];
        for (int pos = 0; pos < 16; pos++) {
            for (int x = 0; x < 256; x++) {
                Arrays.fill(blk, 0); blk[pos] = PI[x]; lTransform(blk, mul);
                LS_HI[pos][x] = hiOf(blk); LS_LO[pos][x] = loOf(blk);
                Arrays.fill(blk, 0); blk[pos] = x; lInverse(blk, mul);
                LSI_HI[pos][x] = hiOf(blk); LSI_LO[pos][x] = loOf(blk);
            }
        }
        for (int i = 1; i <= 32; i++) {
            Arrays.fill(blk, 0); blk[15] = i; lTransform(blk, mul);
            RC_HI[i - 1] = hiOf(blk); RC_LO[i - 1] = loOf(blk);
        }
    }

    private static long[] tableXor(long[][] th, long[][] tl, long hi, long lo) {
        long rh = 0, rl = 0;
        for (int i = 0; i < 8; i++) {
            int b = (int) ((hi >>> (56 - 8 * i)) & 0xff);
            rh ^= th[i][b]; rl ^= tl[i][b];
        }
        for (int i = 8; i < 16; i++) {
            int b = (int) ((lo >>> (56 - 8 * (i - 8))) & 0xff);
            rh ^= th[i][b]; rl ^= tl[i][b];
        }
        return new long[]{rh, rl};
    }

    private static long sInv(long v) {
        long r = 0;
        for (int i = 0; i < 8; i++) r |= ((long) PI_INV[(int) ((v >>> (56 - 8 * i)) & 0xff)]) << (56 - 8 * i);
        return r;
    }

    static long be64(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[off + i] & 0xff);
        return v;
    }

    static void putBe64(long v, byte[] b, int off) {
        for (int i = 0; i < 8; i++) b[off + i] = (byte) (v >>> (56 - 8 * i));
    }

    /** GOST R 34.12-2015 block cipher, 256-bit key. */
    public static final class Kuznyechik {
        private final long[] kh = new long[10], kl = new long[10];

        public Kuznyechik(byte[] key) {
            if (key == null || key.length != 32) throw new IllegalArgumentException("Kuznyechik key must be 32 bytes");
            long k1h = be64(key, 0), k1l = be64(key, 8), k2h = be64(key, 16), k2l = be64(key, 24);
            kh[0] = k1h; kl[0] = k1l; kh[1] = k2h; kl[1] = k2l;
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 8; j++) {
                    long[] t = tableXor(LS_HI, LS_LO, k1h ^ RC_HI[8 * i + j], k1l ^ RC_LO[8 * i + j]);
                    long nh = t[0] ^ k2h, nl = t[1] ^ k2l;
                    k2h = k1h; k2l = k1l; k1h = nh; k1l = nl;
                }
                kh[2 * i + 2] = k1h; kl[2 * i + 2] = k1l; kh[2 * i + 3] = k2h; kl[2 * i + 3] = k2l;
            }
        }

        long[] encrypt(long hi, long lo) {
            for (int i = 0; i < 9; i++) {
                long[] t = tableXor(LS_HI, LS_LO, hi ^ kh[i], lo ^ kl[i]);
                hi = t[0]; lo = t[1];
            }
            return new long[]{hi ^ kh[9], lo ^ kl[9]};
        }

        long[] decrypt(long hi, long lo) {
            hi ^= kh[9]; lo ^= kl[9];
            for (int i = 8; i >= 0; i--) {
                long[] t = tableXor(LSI_HI, LSI_LO, hi, lo);
                hi = sInv(t[0]) ^ kh[i]; lo = sInv(t[1]) ^ kl[i];
            }
            return new long[]{hi, lo};
        }

        public byte[] encryptBlock(byte[] block) {
            if (block.length != 16) throw new IllegalArgumentException("block must be 16 bytes");
            long[] r = encrypt(be64(block, 0), be64(block, 8));
            byte[] out = new byte[16]; putBe64(r[0], out, 0); putBe64(r[1], out, 8);
            return out;
        }

        public byte[] decryptBlock(byte[] block) {
            if (block.length != 16) throw new IllegalArgumentException("block must be 16 bytes");
            long[] r = decrypt(be64(block, 0), be64(block, 8));
            byte[] out = new byte[16]; putBe64(r[0], out, 0); putBe64(r[1], out, 8);
            return out;
        }
    }

    // ── MGM — R 1323565.1.026-2019 / RFC 9058 ───────────────────────────────
    /** a ⊗ b in GF(2^128), f(w) = w^128 + w^7 + w^2 + w + 1, big-endian integers, bit 0 = w^0. */
    private static long[] gf128(long ah, long al, long bh, long bl) {
        long ph = 0, pl = 0;
        for (int i = 0; i < 128; i++) {
            if ((bl & 1) != 0) { ph ^= ah; pl ^= al; }
            boolean carry = ah < 0;
            ah = (ah << 1) | (al >>> 63);
            al <<= 1;
            if (carry) al ^= 0x87;
            bl = (bl >>> 1) | (bh << 63);
            bh >>>= 1;
        }
        return new long[]{ph, pl};
    }

    private static void checkNonce(byte[] nonce) {
        if (nonce == null || nonce.length != 16 || (nonce[0] & 0x80) != 0)
            throw new IllegalArgumentException("MGM nonce must be 16 bytes with the top bit clear");
    }

    private static byte[] keystreamXor(Kuznyechik c, byte[] nonce, byte[] data) {
        long[] y = c.encrypt(be64(nonce, 0), be64(nonce, 8));
        byte[] out = new byte[data.length], ks = new byte[16];
        for (int off = 0; off < data.length; off += 16) {
            long[] k = c.encrypt(y[0], y[1]);
            putBe64(k[0], ks, 0); putBe64(k[1], ks, 8);
            int n = Math.min(16, data.length - off);
            for (int i = 0; i < n; i++) out[off + i] = (byte) (data[off + i] ^ ks[i]);
            y[1]++;                                         // incr_r: low 64-bit half
        }
        return out;
    }

    private static byte[] mgmTag(Kuznyechik c, byte[] nonce, byte[] aad, byte[] ct) {
        long[] z = c.encrypt(be64(nonce, 0) | Long.MIN_VALUE, be64(nonce, 8));
        long ah = 0, al = 0;
        byte[] blk = new byte[16];
        for (byte[] part : new byte[][]{aad, ct}) {
            for (int off = 0; off < part.length; off += 16) {
                Arrays.fill(blk, (byte) 0);
                System.arraycopy(part, off, blk, 0, Math.min(16, part.length - off));
                long[] h = c.encrypt(z[0], z[1]);
                long[] m = gf128(h[0], h[1], be64(blk, 0), be64(blk, 8));
                ah ^= m[0]; al ^= m[1];
                z[0]++;                                     // incr_l: high 64-bit half
            }
        }
        long[] h = c.encrypt(z[0], z[1]);
        long[] m = gf128(h[0], h[1], (long) aad.length * 8, (long) ct.length * 8);
        ah ^= m[0]; al ^= m[1];
        long[] t = c.encrypt(ah, al);
        byte[] tag = new byte[16]; putBe64(t[0], tag, 0); putBe64(t[1], tag, 8);
        return tag;
    }

    /** ciphertext ‖ 16-byte tag. */
    public static byte[] mgmSeal(Kuznyechik c, byte[] nonce, byte[] plaintext, byte[] aad) {
        checkNonce(nonce);
        byte[] ct = keystreamXor(c, nonce, plaintext);
        byte[] tag = mgmTag(c, nonce, aad, ct);
        byte[] out = Arrays.copyOf(ct, ct.length + 16);
        System.arraycopy(tag, 0, out, ct.length, 16);
        return out;
    }

    /** Opens ciphertext ‖ tag; throws {@link GeneralSecurityException} when the tag does not verify. */
    public static byte[] mgmOpen(Kuznyechik c, byte[] nonce, byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
        checkNonce(nonce);
        if (ciphertext == null || ciphertext.length < 16) throw new GeneralSecurityException("MGM ciphertext too short");
        byte[] ct = Arrays.copyOf(ciphertext, ciphertext.length - 16);
        byte[] tag = Arrays.copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length);
        if (!MessageDigest.isEqual(mgmTag(c, nonce, aad, ct), tag)) throw new GeneralSecurityException("MGM tag mismatch");
        return keystreamXor(c, nonce, ct);
    }

    // ── Curve id-tc26-gost-3410-2012-256-paramSetB, VKO (RFC 7836 §4.3) ─────
    static final BigInteger P = new BigInteger(GostConsts.CURVE_P, 16);
    static final BigInteger A = new BigInteger(GostConsts.CURVE_A, 16);
    static final BigInteger B = new BigInteger(GostConsts.CURVE_B, 16);
    static final BigInteger Q = new BigInteger(GostConsts.CURVE_Q, 16);
    static final BigInteger[] G = {new BigInteger(GostConsts.CURVE_GX, 16), new BigInteger(GostConsts.CURVE_GY, 16)};
    private static final BigInteger TWO = BigInteger.valueOf(2), THREE = BigInteger.valueOf(3), FOUR = BigInteger.valueOf(4), EIGHT = BigInteger.valueOf(8);
    private static final BigInteger[] J_INF = {BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO};

    private static BigInteger[] jdouble(BigInteger[] p) {
        BigInteger x1 = p[0], y1 = p[1], z1 = p[2];
        if (y1.signum() == 0) return J_INF;
        BigInteger s = FOUR.multiply(x1).multiply(y1).multiply(y1).mod(P);
        BigInteger z1sq = z1.multiply(z1).mod(P);
        BigInteger m = THREE.multiply(x1).multiply(x1).add(A.multiply(z1sq).multiply(z1sq)).mod(P);
        BigInteger x3 = m.multiply(m).subtract(TWO.multiply(s)).mod(P);
        BigInteger y3 = m.multiply(s.subtract(x3)).subtract(EIGHT.multiply(y1.modPow(FOUR, P))).mod(P);
        BigInteger z3 = TWO.multiply(y1).multiply(z1).mod(P);
        return new BigInteger[]{x3, y3, z3};
    }

    private static BigInteger[] jadd(BigInteger[] p1, BigInteger[] p2) {
        if (p1[2].signum() == 0) return p2;
        if (p2[2].signum() == 0) return p1;
        BigInteger z1sq = p1[2].multiply(p1[2]).mod(P), z2sq = p2[2].multiply(p2[2]).mod(P);
        BigInteger u1 = p1[0].multiply(z2sq).mod(P), u2 = p2[0].multiply(z1sq).mod(P);
        BigInteger s1 = p1[1].multiply(z2sq).multiply(p2[2]).mod(P), s2 = p2[1].multiply(z1sq).multiply(p1[2]).mod(P);
        if (u1.equals(u2)) return s1.equals(s2) ? jdouble(p1) : J_INF;
        BigInteger h = u2.subtract(u1).mod(P), r = s2.subtract(s1).mod(P);
        BigInteger h2 = h.multiply(h).mod(P), h3 = h2.multiply(h).mod(P);
        BigInteger x3 = r.multiply(r).subtract(h3).subtract(TWO.multiply(u1).multiply(h2)).mod(P);
        BigInteger y3 = r.multiply(u1.multiply(h2).subtract(x3)).subtract(s1.multiply(h3)).mod(P);
        BigInteger z3 = h.multiply(p1[2]).multiply(p2[2]).mod(P);
        return new BigInteger[]{x3, y3, z3};
    }

    private static BigInteger[] toAffine(BigInteger[] j) {
        if (j[2].signum() == 0) return null;
        BigInteger zi = j[2].modInverse(P), zi2 = zi.multiply(zi).mod(P);
        return new BigInteger[]{j[0].multiply(zi2).mod(P), j[1].multiply(zi2).multiply(zi).mod(P)};
    }

    /** k·pt (affine {x, y}; null = point at infinity) by double-and-add in Jacobian coordinates. */
    static BigInteger[] mul(BigInteger k, BigInteger[] pt) {
        k = k.mod(Q);
        if (k.signum() == 0 || pt == null) return null;
        BigInteger[] result = J_INF, addend = {pt[0], pt[1], BigInteger.ONE};
        for (int i = 0, n = k.bitLength(); i < n; i++) {
            if (k.testBit(i)) result = jadd(result, addend);
            addend = jdouble(addend);
        }
        return toAffine(result);
    }

    static boolean onCurve(BigInteger[] pt) {
        if (pt == null) return false;
        BigInteger x = pt[0], y = pt[1];
        if (x.signum() < 0 || x.compareTo(P) >= 0 || y.signum() < 0 || y.compareTo(P) >= 0) return false;
        BigInteger lhs = y.multiply(y).mod(P);
        BigInteger rhs = x.multiply(x).multiply(x).add(A.multiply(x)).add(B).mod(P);
        return lhs.equals(rhs);
    }

    private static byte[] le32(BigInteger v) {
        byte[] be = v.toByteArray(), out = new byte[32];       // big-endian, possibly with a sign byte
        int n = Math.min(be.length, 32);
        for (int i = 0; i < n; i++) out[i] = be[be.length - 1 - i];
        return out;
    }

    private static BigInteger fromLe(byte[] b, int off, int len) {
        byte[] be = new byte[len];
        for (int i = 0; i < len; i++) be[i] = b[off + len - 1 - i];
        return new BigInteger(1, be);
    }

    /** X ‖ Y, each 32 bytes little-endian — the GOST public-key encoding. */
    static byte[] encodePoint(BigInteger[] pt) {
        byte[] out = new byte[64];
        System.arraycopy(le32(pt[0]), 0, out, 0, 32);
        System.arraycopy(le32(pt[1]), 0, out, 32, 32);
        return out;
    }

    /** Decodes and validates (on the curve; prime order ⇒ in the group). */
    static BigInteger[] decodePoint(byte[] raw) {
        if (raw == null || raw.length != 64) throw new IllegalArgumentException("GOST public key must be 64 bytes (X‖Y little-endian)");
        BigInteger[] pt = {fromLe(raw, 0, 32), fromLe(raw, 32, 32)};
        if (!onCurve(pt)) throw new IllegalArgumentException("point is not on the GOST curve");
        return pt;
    }

    private static byte[] be32(BigInteger d) {
        byte[] be = d.toByteArray(), out = new byte[32];
        int n = Math.min(be.length, 32);
        System.arraycopy(be, be.length - n, out, 32 - n, n);
        return out;
    }

    /** {privateB64, publicB64}: 32-byte big-endian scalar d ∈ [1, q−1] and the 64-byte X‖Y little-endian point d·G. */
    public static String[] generateGostKeyPair() {
        SecureRandom rnd = new SecureRandom();
        byte[] buf = new byte[32];
        BigInteger d;
        do { rnd.nextBytes(buf); d = new BigInteger(1, buf); } while (d.signum() == 0 || d.compareTo(Q) >= 0);
        byte[] pk = encodePoint(mul(d, G));
        Base64.Encoder enc = Base64.getEncoder();
        return new String[]{enc.encodeToString(be32(d)), enc.encodeToString(pk)};
    }

    /** VKO_GOSTR3410_2012_256: Streebog-256( X‖Y little-endian of (UKM·d)·peer ), UKM 8 bytes little-endian ≥ 1. */
    static byte[] vko(BigInteger d, BigInteger[] peer, byte[] ukm) {
        if (ukm == null || ukm.length != 8) throw new IllegalArgumentException("UKM must be 8 bytes");
        BigInteger u = fromLe(ukm, 0, 8);
        if (u.signum() == 0) throw new IllegalArgumentException("UKM must be non-zero");
        BigInteger[] shared = mul(u.multiply(d).mod(Q), peer);
        if (shared == null) throw new IllegalArgumentException("degenerate shared point");
        return streebog256(encodePoint(shared));
    }

    private static final String DOES_NOT_OPEN = "sealed value does not open with this private key (wrong key, or the token is bound to another key)";

    /** Opens the GOST envelope (flat pairs alg/v/epk/ukm/nonce/ct) with the base64 32-byte private scalar;
     *  {@code name} is the secret's name (AAD). Returns the payload pairs ({@code value}, {@code login}, …). */
    public static Map<String, String> unsealGost(Map<String, String> env, String privateKeyB64, String name) throws IOException {
        byte[] skRaw, epk, ukm, nonce, ct;
        BigInteger d;
        try {
            skRaw = Base64.getDecoder().decode(privateKeyB64);
            if (skRaw.length != 32) throw new IllegalArgumentException("GOST private key must be 32 bytes (big-endian scalar)");
            d = new BigInteger(1, skRaw);
            if (d.signum() == 0 || d.compareTo(Q) >= 0) throw new IllegalArgumentException("GOST private key out of range");
            epk = Base64.getDecoder().decode(req(env, "epk"));
            ukm = Base64.getDecoder().decode(req(env, "ukm"));
            nonce = Base64.getDecoder().decode(req(env, "nonce"));
            ct = Base64.getDecoder().decode(req(env, "ct"));
        } catch (IllegalArgumentException e) {
            throw new IOException("vault: sealed envelope: " + e.getMessage(), e);
        }
        try {
            byte[] ourPk = encodePoint(mul(d, G));
            BigInteger[] peer = decodePoint(epk);
            byte[] kek = vko(d, peer, ukm);
            byte[] seed = Arrays.copyOf(epk, 128);
            System.arraycopy(ourPk, 0, seed, 64, 64);
            byte[] key = kdfTree256(kek, LABEL.getBytes(StandardCharsets.UTF_8), seed);
            byte[] pt = mgmOpen(new Kuznyechik(key), nonce, ct, name.getBytes(StandardCharsets.UTF_8));
            return VaultClient.parseFlat(new String(pt, StandardCharsets.UTF_8));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new VaultClient.VaultException(0, DOES_NOT_OPEN);
        }
    }

    private static String req(Map<String, String> env, String k) {
        String v = env.get(k);
        if (v == null) throw new IllegalArgumentException("envelope field '" + k + "' missing");
        return v;
    }
}
