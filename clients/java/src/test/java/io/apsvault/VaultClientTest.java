package io.apsvault;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
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

    static void reply(com.sun.net.httpserver.HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    public static void main(String[] args) throws Exception {
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/", ex -> {
            String auth = ex.getRequestHeaders().getFirst("Authorization");
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
