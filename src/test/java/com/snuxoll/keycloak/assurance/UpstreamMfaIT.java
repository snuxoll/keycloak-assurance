package com.snuxoll.keycloak.assurance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

import com.snuxoll.keycloak.assurance.it.ItGoogleIdentityProviderFactory;
import com.snuxoll.keycloak.assurance.it.ItMicrosoftIdentityProviderFactory;

import dasniko.testcontainers.keycloak.KeycloakContainer;

/**
 * End to end through a real Keycloak: an "upstream" realm plays the external IdP and asserts a fixed amr per
 * client; a "downstream" realm brokers to it with the upstream MFA mapper, condition and protocol mapper.
 */
class UpstreamMfaIT {

    private static final String IMAGE = "quay.io/keycloak/keycloak:26.8.1";
    private static final String CALLBACK = "http://localhost/callback";

    // Back-channel calls (token, JWKS) are made by Keycloak itself, from inside the container.
    private static final String INTERNAL_UPSTREAM = "http://localhost:8080/realms/upstream";

    private static KeycloakContainer keycloak;
    private static String baseUrl;

    @BeforeAll
    static void start() throws Exception {
        // test-classes carries the it.* provider factories that point the Google/Microsoft overrides at upstream.
        keycloak = new KeycloakContainer(IMAGE)
                .withProviderClassesFrom("target/classes", "target/test-classes")
                .withRealmImportFiles("/realms/upstream-realm.json", "/realms/downstream-realm.json");
        keycloak.start();
        baseUrl = keycloak.getAuthServerUrl().replaceAll("/$", "");

        // IdPs are created here rather than imported because the browser-facing URL includes the mapped port.
        String adminToken = adminToken();
        createIdentityProvider(adminToken, "up-mfa", "oidc", upstreamOidcConfig("broker-mfa"));
        createIdentityProvider(adminToken, "up-pwd", "oidc", upstreamOidcConfig("broker-pwd"));
        createIdentityProvider(adminToken, "up-google", ItGoogleIdentityProviderFactory.PROVIDER_ID,
                itConfig("broker-google"));
        // The Microsoft provider always asks for Graph's User.Read; the upstream must know the scope.
        addOptionalScope(adminToken, "broker-entra", "User.Read");
        createIdentityProvider(adminToken, "up-entra", ItMicrosoftIdentityProviderFactory.PROVIDER_ID,
                itConfig("broker-entra"));

        // The production overrides under the built-in ids. These never complete a login (no real Google or
        // Microsoft); the tests only inspect the redirect they produce.
        createIdentityProvider(adminToken, "google", "google", Map.of("clientId", "dummy", "clientSecret", "dummy"));
        createIdentityProvider(adminToken, "microsoft", "microsoft",
                Map.of("clientId", "dummy", "clientSecret", "dummy"));
    }

    @AfterAll
    static void stop() throws IOException {
        if (keycloak != null) {
            // Kept for debugging failed runs.
            Files.writeString(Path.of("target", "keycloak-it.log"), keycloak.getLogs());
            keycloak.stop();
        }
    }

    // Each test uses its own upstream user so first-login and returning-login paths don't depend on test order.

    @Test
    void upstreamMfaSkipsLocalOtpOnFirstLogin() throws Exception {
        LoginResult result = new Browser().login("up-mfa", "alice", "alice");

        assertNotNull(result.code(), () -> "expected a redirect to the app, got page:\n" + result.page());
        assertEquals(List.of("pwd", "mfa"), accessTokenClaims(result.code()).get("amr"));
    }

    @Test
    void upstreamWithoutMfaRequiresLocalOtp() throws Exception {
        // bob only ever logs in through the client that asserts amr ["pwd"]
        LoginResult result = new Browser().login("up-pwd", "bob", "bob");

        assertNull(result.code(), "local OTP should have been required before reaching the app");
        assertTrue(isOtpPage(result.page()), () -> "expected an OTP page, got:\n" + result.page());
    }

    @Test
    void returningUserStillSkipsLocalOtp() throws Exception {
        // The first login creates and links the user; the second takes the existing-link path.
        assertNotNull(new Browser().login("up-mfa", "carol", "carol").code());

        LoginResult again = new Browser().login("up-mfa", "carol", "carol");
        assertNotNull(again.code(), () -> "expected a redirect to the app, got page:\n" + again.page());
        assertEquals(List.of("pwd", "mfa"), accessTokenClaims(again.code()).get("amr"));
    }

    @Test
    void googleOverrideIsUsedAndRequestsAmrClaims() throws Exception {
        URI redirect = new Browser().redirectToIdp("google");

        assertEquals("accounts.google.com", redirect.getHost());
        Map<String, String> query = queryParams(redirect);
        assertNotNull(query.get("claims"), () -> "no claims param in " + redirect);
        assertEquals(
                JsonSerialization.readValue(
                        "{\"id_token\":{\"amr\":{\"essential\":true},\"auth_time\":{\"essential\":true}}}", Map.class),
                JsonSerialization.readValue(query.get("claims"), Map.class));
    }

    @Test
    void microsoftOverrideIsUsedAndRequestsAnIdToken() throws Exception {
        URI redirect = new Browser().redirectToIdp("microsoft");

        assertEquals("login.microsoftonline.com", redirect.getHost());
        assertEquals("/common/oauth2/v2.0/authorize", redirect.getPath());
        List<String> scopes = List.of(queryParams(redirect).get("scope").split(" "));
        // The built-in provider sends only User.read, and never gets an ID token.
        assertTrue(scopes.contains("openid") && scopes.contains("User.Read"), () -> "scope was " + scopes);
        assertNotNull(queryParams(redirect).get("nonce"));
    }

    @Test
    void googleProviderCarriesUpstreamMfa() throws Exception {
        LoginResult result = new Browser().login("up-google", "erin", "erin");

        assertNotNull(result.code(), () -> "expected a redirect to the app, got page:\n" + result.page());
        assertEquals(List.of("pwd", "mfa"), accessTokenClaims(result.code()).get("amr"));
    }

    @Test
    void microsoftProviderCarriesUpstreamMfaAndKeysOnGraphId() throws Exception {
        LoginResult result = new Browser().login("up-entra", "dave", "dave");

        assertNotNull(result.code(), () -> "expected a redirect to the app, got page:\n" + result.page());
        assertEquals(List.of("pwd", "mfa"), accessTokenClaims(result.code()).get("amr"));

        // The link must use the Graph id (as the built-in provider does), not the ID token's sub.
        List<Map<String, Object>> links = federatedIdentities("dave@example.com");
        assertEquals(1, links.size(), () -> "links: " + links);
        assertEquals("4a1b2c3d4e5f6071", links.get(0).get("userId"));
    }

    private static boolean isOtpPage(String html) {
        Document doc = Jsoup.parse(html);
        return doc.selectFirst("input[name=otp]") != null || doc.selectFirst("input[name=totp]") != null;
    }

    // --- setup -------------------------------------------------------------------------------------------------

    private static String adminToken() throws Exception {
        Map<String, Object> token = postForm(baseUrl + "/realms/master/protocol/openid-connect/token", Map.of(
                "grant_type", "password",
                "client_id", "admin-cli",
                "username", keycloak.getAdminUsername(),
                "password", keycloak.getAdminPassword()));
        return (String) token.get("access_token");
    }

    /** Generic OIDC IdP config for an upstream realm client whose secret is "{clientId}-secret". */
    private static Map<String, String> upstreamOidcConfig(String clientId) {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", clientId);
        config.put("clientSecret", clientId + "-secret");
        config.put("clientAuthMethod", "client_secret_post");
        config.put("authorizationUrl", baseUrl + "/realms/upstream/protocol/openid-connect/auth");
        config.put("tokenUrl", INTERNAL_UPSTREAM + "/protocol/openid-connect/token");
        config.put("jwksUrl", INTERNAL_UPSTREAM + "/protocol/openid-connect/certs");
        config.put("useJwksUrl", "true");
        config.put("validateSignature", "true");
        // The upstream stamps tokens with the frontend URL the user logged in through, not the back-channel one.
        config.put("issuer", baseUrl + "/realms/upstream");
        config.put("defaultScope", "openid profile email");
        config.put("syncMode", "IMPORT");
        return config;
    }

    /** Config for the it.* providers, which take their endpoints from it.* keys (see ItEndpoints). */
    private static Map<String, String> itConfig(String clientId) {
        Map<String, String> oidc = upstreamOidcConfig(clientId);
        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", clientId);
        config.put("clientSecret", oidc.get("clientSecret"));
        config.put("clientAuthMethod", "client_secret_post");
        config.put("syncMode", "IMPORT");
        config.put("it.authorizationUrl", oidc.get("authorizationUrl"));
        config.put("it.tokenUrl", oidc.get("tokenUrl"));
        config.put("it.jwksUrl", oidc.get("jwksUrl"));
        config.put("it.issuer", oidc.get("issuer"));
        return config;
    }

    private static void createIdentityProvider(String adminToken, String alias, String providerId,
                                               Map<String, String> config) throws Exception {
        Map<String, Object> idp = new LinkedHashMap<>();
        idp.put("alias", alias);
        idp.put("providerId", providerId);
        idp.put("enabled", true);
        idp.put("trustEmail", true);
        idp.put("postBrokerLoginFlowAlias", "post-broker-mfa");
        idp.put("config", config);
        postJson(adminToken, "/admin/realms/downstream/identity-provider/instances", idp);

        postJson(adminToken, "/admin/realms/downstream/identity-provider/instances/" + alias + "/mappers", Map.of(
                "name", "upstream amr",
                "identityProviderAlias", alias,
                "identityProviderMapper", UpstreamAmrIdentityProviderMapper.PROVIDER_ID,
                "config", Map.of("syncMode", "INHERIT")));
    }

    @SuppressWarnings("unchecked")
    private static void addOptionalScope(String adminToken, String clientId, String scope) throws Exception {
        String location = postJson(adminToken, "/admin/realms/upstream/client-scopes",
                Map.of("name", scope, "protocol", "openid-connect"));
        String scopeId = location.substring(location.lastIndexOf('/') + 1);
        List<Map<String, Object>> clients = getJson(adminToken, "/admin/realms/upstream/clients?clientId=" + clientId,
                List.class);
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/upstream/clients/"
                        + clients.get(0).get("id") + "/optional-client-scopes/" + scopeId))
                .header("Authorization", "Bearer " + adminToken)
                .PUT(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(204, response.statusCode(), () -> "adding scope failed: " + response.body());
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> federatedIdentities(String username) throws Exception {
        String adminToken = adminToken();
        List<Map<String, Object>> users = getJson(adminToken, "/admin/realms/downstream/users?exact=true&username="
                + URLEncoder.encode(username, StandardCharsets.UTF_8), List.class);
        assertEquals(1, users.size(), () -> "users named " + username + ": " + users);
        return getJson(adminToken, "/admin/realms/downstream/users/" + users.get(0).get("id") + "/federated-identity",
                List.class);
    }

    private static <T> T getJson(String adminToken, String path, Class<T> type) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + adminToken)
                .GET()
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "GET " + path + " failed: " + response.body());
        return JsonSerialization.readValue(response.body(), type);
    }

    /** Returns the Location of the created resource. */
    private static String postJson(String adminToken, String path, Object body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + adminToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JsonSerialization.writeValueAsString(body)))
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, response.statusCode(), () -> "POST " + path + " failed: " + response.body());
        return response.headers().firstValue("Location").orElse("");
    }

    // --- tokens ------------------------------------------------------------------------------------------------

    private static Map<String, Object> accessTokenClaims(String code) throws Exception {
        Map<String, Object> tokens = postForm(baseUrl + "/realms/downstream/protocol/openid-connect/token", Map.of(
                "grant_type", "authorization_code",
                "client_id", "app",
                "redirect_uri", CALLBACK,
                "code", code));
        String accessToken = (String) tokens.get("access_token");
        assertNotNull(accessToken, () -> "token exchange failed: " + tokens);
        String payload = accessToken.split("\\.")[1];
        return JsonSerialization.readValue(Base64.getUrlDecoder().decode(payload), Map.class);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> postForm(String url, Map<String, String> form) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(encode(form)))
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        return JsonSerialization.readValue(response.body(), Map.class);
    }

    private static String encode(Map<String, String> form) {
        return form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    private static Map<String, String> queryParams(URI uri) {
        Map<String, String> params = new LinkedHashMap<>();
        if (uri.getRawQuery() != null) {
            for (String pair : uri.getRawQuery().split("&")) {
                String[] kv = pair.split("=", 2);
                params.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                        kv.length == 2 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
            }
        }
        return params;
    }

    // --- browser -----------------------------------------------------------------------------------------------

    /** Where a login ended up: the app's authorization code, or the page Keycloak stopped on. */
    record LoginResult(String code, String page) {
    }

    /**
     * A minimal browser: follows redirects by hand so it can stop at the app's callback, and keeps its own cookie
     * jar because java.net.CookieManager won't send Secure cookies over http or match a bare "localhost" domain.
     */
    private static final class Browser {

        private final HttpClient http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        // path -> (name -> value); everything here is on one host
        private final Map<String, Map<String, String>> cookies = new LinkedHashMap<>();

        /** Starts a brokered login and returns the first redirect that leaves Keycloak, without following it. */
        URI redirectToIdp(String idpAlias) throws Exception {
            HttpResponse<String> response = get(authUrl(idpAlias));
            URI keycloakUri = URI.create(baseUrl);
            for (int hops = 0; hops < 20; hops++) {
                int status = response.statusCode();
                URI next = response.uri().resolve(response.headers().firstValue("Location").orElseThrow(
                        () -> new AssertionError("no redirect to the IdP; got " + status)));
                if (!keycloakUri.getAuthority().equals(next.getAuthority())) {
                    return next;
                }
                response = get(next);
            }
            throw new IllegalStateException("too many redirects");
        }

        private static URI authUrl(String idpAlias) {
            return URI.create(baseUrl + "/realms/downstream/protocol/openid-connect/auth?" + encode(Map.of(
                    "client_id", "app",
                    "redirect_uri", CALLBACK,
                    "response_type", "code",
                    "scope", "openid",
                    "state", "state",
                    "nonce", "nonce",
                    "kc_idp_hint", idpAlias)));
        }

        LoginResult login(String idpAlias, String username, String password) throws Exception {
            Page page = follow(get(authUrl(idpAlias)));
            if (page.code() != null) {
                return new LoginResult(page.code(), null);
            }

            Element form = Jsoup.parse(page.body(), page.uri().toString()).selectFirst("form#kc-form-login");
            assertNotNull(form, () -> "expected the upstream login form, got " + page.status() + " " + page.uri() + ":\n" + page.body());
            URI action = URI.create(form.absUrl("action"));
            HttpRequest submit = withCookies(HttpRequest.newBuilder(action), action)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(encode(Map.of(
                            "username", username,
                            "password", password,
                            "credentialId", ""))))
                    .build();

            Page result = follow(send(submit));
            return new LoginResult(result.code(), result.body());
        }

        private HttpResponse<String> get(URI uri) throws IOException, InterruptedException {
            return send(withCookies(HttpRequest.newBuilder(uri), uri).GET().build());
        }

        private HttpResponse<String> send(HttpRequest request) throws IOException, InterruptedException {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            for (String header : response.headers().allValues("Set-Cookie")) {
                store(header);
            }
            return response;
        }

        private void store(String header) {
            String[] parts = header.split(";");
            String[] nameValue = parts[0].trim().split("=", 2);
            String path = "/";
            boolean expired = false;
            for (int i = 1; i < parts.length; i++) {
                String[] attr = parts[i].trim().split("=", 2);
                if (attr[0].equalsIgnoreCase("Path") && attr.length == 2) {
                    path = attr[1];
                } else if (attr[0].equalsIgnoreCase("Max-Age") && attr.length == 2 && attr[1].equals("0")) {
                    expired = true;
                } else if (attr[0].equalsIgnoreCase("Expires") && attr.length == 2 && attr[1].contains("1970")) {
                    expired = true;
                }
            }
            Map<String, String> atPath = cookies.computeIfAbsent(path, k -> new LinkedHashMap<>());
            if (expired || nameValue.length < 2 || nameValue[1].isEmpty()) {
                atPath.remove(nameValue[0]);
            } else {
                atPath.put(nameValue[0], nameValue[1]);
            }
        }

        private HttpRequest.Builder withCookies(HttpRequest.Builder builder, URI uri) {
            String path = uri.getPath() == null || uri.getPath().isEmpty() ? "/" : uri.getPath();
            String header = cookies.entrySet().stream()
                    .filter(e -> path.startsWith(e.getKey()))
                    .flatMap(e -> e.getValue().entrySet().stream())
                    .map(e -> e.getKey() + "=" + e.getValue())
                    .collect(Collectors.joining("; "));
            return header.isEmpty() ? builder : builder.header("Cookie", header);
        }

        private Page follow(HttpResponse<String> response) throws IOException, InterruptedException {
            for (int hops = 0; hops < 20; hops++) {
                int status = response.statusCode();
                if (status < 300 || status >= 400) {
                    return new Page(response.statusCode(), response.uri(), response.body(), null);
                }
                URI next = response.uri().resolve(response.headers().firstValue("Location").orElseThrow());
                if (next.toString().startsWith(CALLBACK)) {
                    return new Page(302, next, null, queryParams(next).get("code"));
                }
                response = get(next);
            }
            throw new IllegalStateException("too many redirects");
        }


        private record Page(int status, URI uri, String body, String code) {
        }
    }
}
