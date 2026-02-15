package com.premiumminds.datagrip.vault;

import com.google.common.base.Throwables;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.intellij.database.access.DatabaseCredentials;
import com.intellij.database.dataSource.DatabaseAuthProvider;
import com.intellij.database.dataSource.DatabaseConnectionConfig;
import com.intellij.database.dataSource.DatabaseConnectionPoint;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.NonNls;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class VaultKvV2DatabaseAuthProvider implements DatabaseAuthProvider {

    private static final Logger logger = Logger.getInstance(VaultKvV2DatabaseAuthProvider.class);
    private static final String PROP_LOG_RESPONSE_BODY = "datagrip.vault.logResponseBody";

    public static final String PROP_SECRET = "vault_secret";
    public static final String PROP_ADDRESS = "vault_address";
    public static final String PROP_NAMESPACE = "vault_namespace";
    public static final String PROP_TOKEN_FILE = "vault_token_file";
    public static final String PROP_USERNAME_KEY = "vault_username_key";
    public static final String PROP_PASSWORD_KEY = "vault_passwd_key";

    private static final String ENV_VAULT_AGENT_ADDR = "VAULT_AGENT_ADDR";
    private static final String ENV_VAULT_ADDR = "VAULT_ADDR";
    private static final String ENV_VAULT_NAMESPACE = "VAULT_NAMESPACE";
    private static final String ENV_VAULT_CONFIG_PATH = "VAULT_CONFIG_PATH";
    private static final String DEFAULT_VAULT_CONFIG_FILE = ".vault";
    private static final String DEFAULT_VAULT_TOKEN_FILE = ".vault-token";
    private static final String ERROR_VAULT_ADDRESS_NOT_DEFINED = "Vault address not defined";
    private static final String ERROR_VAULT_SECRET_NOT_DEFINED = "Vault secret not defined";
    private static final String ERROR_VAULT_TOKEN_NOT_DEFINED = "Vault token not defined";

    private static final String HEADER_VAULT_TOKEN = "X-Vault-Token";
    private static final String HEADER_VAULT_NAMESPACE = "X-Vault-Namespace";

    private static final String REDACTED = "<redacted>";

    private static final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Override
    public @NonNls @NotNull String getId() {
        return "vault_kv_v2";
    }

    @Override
    public @Nls @NotNull String getDisplayName() {
        return "Vault (KV v2)";
    }

    @NotNull
    @Override
    public ApplicabilityLevel.Result getApplicability(@NotNull DatabaseConnectionPoint point, @NotNull DatabaseAuthProvider.ApplicabilityLevel level) {
        return ApplicabilityLevel.Result.APPLICABLE;
    }

    @Override
    public @Nullable CompletionStage<@NotNull ProtoConnection> intercept(@NotNull ProtoConnection protoConnection, boolean b) {
        try {
            final var address = getAddress(protoConnection);
            final var secret = getSecret(protoConnection);
            final var namespace = getNamespace(protoConnection);

            logger.info("Address used: " + address);
            logger.info("Secret used: " + secret);
            if (namespace != null && !namespace.isBlank()) {
                logger.info("Namespace used: " + namespace);
            }

            final var response = getCredentialsFromVault(protoConnection, address, namespace, secret);

            logger.info("Username used " + response.getData().getUsername());

            protoConnection.getConnectionProperties().put("user", response.getData().getUsername());
            protoConnection.getConnectionProperties().put("password", response.getData().getPassword());

            return CompletableFuture.completedFuture(protoConnection);

        } catch (Exception e) {
            String message = Throwables.getRootCause(e).getMessage();
            if (message == null) message = "Unknown error connecting to Vault";

            var groupManager = NotificationGroupManager.getInstance();
            var group = groupManager.getNotificationGroup("Vault Auth");
            if (group != null) {
                group.createNotification("Vault authentication failed", message, NotificationType.ERROR)
                        .notify(null);
            } else {
                logger.warn("Vault Auth Error: " + message);
            }

            return CompletableFuture.failedStage(new RuntimeException(message, e));
        }
    }

    @Override
    public @Nullable AuthWidget createWidget(@Nullable Project project, @NotNull DatabaseCredentials credentials, @NotNull DatabaseConnectionConfig config) {
        return new VaultKvV2Widget();
    }

    protected DynamicSecretResponse getCredentialsFromVault(
            ProtoConnection protoConnection,
            final String address,
            final String namespace,
            final String secret)
            throws IOException, InterruptedException {
        final var token = getToken(protoConnection, address);

        final var uri = buildVaultReadUri(address, secret);

        final var builder = HttpRequest.newBuilder()
                .GET()
                .uri(uri)
                .header(HEADER_VAULT_TOKEN, token);

        if (namespace != null && !namespace.isBlank()) {
            builder.header(HEADER_VAULT_NAMESPACE, namespace.trim());
        }

        final var request = builder.build();

        logVaultRequest(request);

        final var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        logVaultResponse(response);

        if (response.statusCode() != HttpURLConnection.HTTP_OK) {
            throw vaultReadSecretException(request, response);
        }

        final var responseBody = response.body();
        final var parsed = parseSecretResponse(responseBody, protoConnection.getConnectionPoint());
        validateCredentials(parsed, protoConnection.getConnectionPoint(), request, responseBody);
        return parsed;
    }

    protected RuntimeException vaultReadSecretException(HttpRequest request, HttpResponse<String> response) {
        if (response.statusCode() == HttpURLConnection.HTTP_NOT_FOUND) {
            final StringBuilder sb = new StringBuilder();
            sb.append("Vault secret not found (404). ")
                    .append("Check that the secret path exists and your token has access. ")
                    .append("uri=")
                    .append(request.uri())
                    .append(". Ensure the KV v2 read endpoint is /v1/<mount>/data/<path>.");

            final String vaultErrors = extractVaultErrors(response.body());
            if (vaultErrors != null) {
                sb.append(" Vault says: ").append(vaultErrors);
            }

            return new RuntimeException(sb.toString());
        }

        if (response.statusCode() == HttpURLConnection.HTTP_FORBIDDEN || response.statusCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
            return vaultHttpException("Vault access denied (check token/namespace/policy)", request, response);
        }

        return vaultHttpException("Problem connecting to Vault", request, response);
    }

    protected RuntimeException vaultHttpException(String prefix, HttpRequest request, HttpResponse<String> response) {
        return new RuntimeException(vaultHttpMessage(prefix, request, response));
    }

    protected String vaultHttpMessage(String prefix, HttpRequest request, HttpResponse<String> response) {
        final StringBuilder sb = new StringBuilder();
        sb.append(prefix)
                .append(": status=")
                .append(response.statusCode())
                .append(", uri=")
                .append(request.uri());

        final String body = response.body();
        final String vaultErrors = extractVaultErrors(body);
        if (vaultErrors != null) {
            sb.append(", errors=").append(vaultErrors);
        }

        return sb.toString();
    }

    protected static @Nullable String extractVaultErrors(@Nullable String body) {
        if (body == null || body.isBlank()) return null;

        try {
            final var err = new Gson().fromJson(body, VaultErrorResponse.class);
            if (err == null || err.getErrors() == null || err.getErrors().isEmpty()) {
                return null;
            }
            return String.join("; ", err.getErrors());
        } catch (Exception ignored) {
            return null;
        }
    }

    protected static String truncate(String s, int maxLen) {
        if (s == null) return null;
        if (s.length() <= maxLen) return s;
        return s.substring(0, Math.max(0, maxLen - 3)) + "...";
    }

    protected URI buildVaultReadUri(String address, String secret) {
        final String normalizedSecret = normalizeKvV2PathIfNeeded(secret);
        return URI.create(address).resolve("/v1/").resolve(normalizedSecret);
    }

    /**
     * Normalize a KV v2 secret path into the read endpoint form: <mount>/data/<path>.
     *
     * Assumptions:
     * - The mount is the first path segment.
     * - If the segment right after the mount is already "data" or "metadata",
     *   the path is treated as normalized and returned unchanged.
     *
     * This avoids false positives where "data" or "metadata" appear later in the path.
     */
    protected String normalizeKvV2PathIfNeeded(String secret) {
        if (secret == null) return null;

        String s = normalizeSecretPath(secret);

        final int firstSlash = s.indexOf('/');
        if (firstSlash <= 0 || firstSlash >= s.length() - 1) {
            return s;
        }

        final String mount = s.substring(0, firstSlash);
        final String rest = s.substring(firstSlash + 1);
        if (rest.startsWith("data/") || rest.startsWith("metadata/")) {
            return s;
        }
        return mount + "/data/" + rest;
    }

    protected String normalizeSecretPath(String secret) {
        if (secret == null) return null;
        String s = secret.trim();
        while (s.startsWith("/")) s = s.substring(1);
        return s;
    }

    private static void logVaultRequest(HttpRequest request) {
        logVaultRequest(request, null);
    }

    private static void logVaultRequest(HttpRequest request, @Nullable String body) {
        if (!logger.isDebugEnabled()) return;

        final var safeHeaders = request.headers().map().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> HEADER_VAULT_TOKEN.equalsIgnoreCase(e.getKey())
                                ? java.util.List.of(REDACTED)
                                : e.getValue()
                ));

        logger.debug("Vault HTTP request: method=" + request.method() +
                ", uri=" + request.uri() +
                ", headers=" + safeHeaders);

        if (body != null) {
            logger.debug("Vault HTTP request body: " + body);
        }
    }

    private static void logVaultResponse(HttpResponse<String> response) {
        if (!logger.isDebugEnabled()) return;

        // Opt-in body logging: set -Ddatagrip.vault.logResponseBody=true when debugging.
        // Keep default off to avoid leaking secrets to logs.
        final boolean logBody = Boolean.getBoolean(PROP_LOG_RESPONSE_BODY);
        final StringBuilder sb = new StringBuilder();
        sb.append("Vault HTTP response: status=")
                .append(response.statusCode())
                .append(", headers=")
                .append(response.headers().map());
        if (logBody) {
            sb.append(", body=").append(response.body());
        }
        logger.debug(sb.toString());
    }

    private static boolean containsEnvPlaceholder(String value, String envVarName) {
        return value != null && value.contains("$" + envVarName + "$");
    }

    protected String getAddress(ProtoConnection protoConnection) {
        final var definedAddress = protoConnection.getConnectionPoint().getAdditionalProperty(PROP_ADDRESS);
        if (definedAddress != null && !definedAddress.isBlank()) {
            if (!containsEnvPlaceholder(definedAddress, ENV_VAULT_AGENT_ADDR)
                    && !containsEnvPlaceholder(definedAddress, ENV_VAULT_ADDR)) {
                return definedAddress;
            }
        } else {
            final String vaultAgentAddrEnv = System.getenv(ENV_VAULT_AGENT_ADDR);
            if (vaultAgentAddrEnv != null && !vaultAgentAddrEnv.isBlank()) {
                final String trimmed = vaultAgentAddrEnv.trim();
                if (!containsEnvPlaceholder(trimmed, ENV_VAULT_AGENT_ADDR)) {
                    return trimmed;
                }
            }
            final String vaultAddrEnv = System.getenv(ENV_VAULT_ADDR);
            if (vaultAddrEnv != null && !vaultAddrEnv.isBlank()) {
                final String trimmed = vaultAddrEnv.trim();
                if (!containsEnvPlaceholder(trimmed, ENV_VAULT_ADDR)) {
                    return trimmed;
                }
            }
        }
        throw new RuntimeException(ERROR_VAULT_ADDRESS_NOT_DEFINED);
    }

    protected String getNamespace(ProtoConnection protoConnection) throws IOException {
        final var definedNamespace = protoConnection.getConnectionPoint().getAdditionalProperty(PROP_NAMESPACE);
        if (definedNamespace != null && !definedNamespace.isBlank()) {
            if (!containsEnvPlaceholder(definedNamespace, ENV_VAULT_NAMESPACE)) {
                return definedNamespace;
            }
        }
        final String vaultNamespaceEnv = System.getenv(ENV_VAULT_NAMESPACE);
        if (vaultNamespaceEnv != null && !vaultNamespaceEnv.isBlank()) {
            final String trimmed = vaultNamespaceEnv.trim();
            if (!containsEnvPlaceholder(trimmed, ENV_VAULT_NAMESPACE)) {
                return trimmed;
            }
        }
        return null;
    }

    protected String getSecret(ProtoConnection protoConnection) {
        final var secret = protoConnection.getConnectionPoint().getAdditionalProperty(PROP_SECRET);
        if (secret != null && !secret.isBlank()) {
            return secret;
        }
        throw new RuntimeException(ERROR_VAULT_SECRET_NOT_DEFINED);
    }

    protected String getToken(ProtoConnection protoConnection, String vaultAddress) throws IOException, InterruptedException {

        final var tokenFile = protoConnection.getConnectionPoint().getAdditionalProperty(PROP_TOKEN_FILE);
        if (tokenFile != null && !tokenFile.isBlank()) {
            final var path = Paths.get(tokenFile);
            if (path.toFile().exists()) {
                return Files.readString(path);
            }
        }

        final var vaultConfigFile = getConfigFile();
        if (vaultConfigFile.toFile().exists()) {
            final String token = getTokenFromVaultTokenHelper(vaultConfigFile, vaultAddress);
            if (token != null) {
                return token;
            }
        }
        final var defaultTokenFilePath = Paths.get(System.getProperty("user.home"), DEFAULT_VAULT_TOKEN_FILE);
        if (defaultTokenFilePath.toFile().exists()) {
            return Files.readString(defaultTokenFilePath);
        }

        throw new RuntimeException(ERROR_VAULT_TOKEN_NOT_DEFINED);
    }

    protected Path getConfigFile() {
        Path vaultConfigPath = Paths.get(System.getProperty("user.home"), DEFAULT_VAULT_CONFIG_FILE);

        final String vaultConfigPathEnv = System.getenv(ENV_VAULT_CONFIG_PATH);
        if (vaultConfigPathEnv != null && !vaultConfigPathEnv.isBlank()) {
            final String trimmed = vaultConfigPathEnv.trim();
            if (!containsEnvPlaceholder(trimmed, ENV_VAULT_CONFIG_PATH)) {
                vaultConfigPath = Paths.get(trimmed);
            }
        }

        return vaultConfigPath;
    }

    protected String getTokenFromVaultTokenHelper(Path configFile, String vaultAddress)
            throws IOException, InterruptedException {
        final Gson gson = new Gson();

        try (FileReader fileReader = new FileReader(configFile.toFile())) {
            final VaultConfig config = gson.fromJson(fileReader, VaultConfig.class);

            if (config.tokenHelper != null && !config.tokenHelper.isBlank()) {
                final ProcessBuilder processBuilder = new ProcessBuilder();
                processBuilder.environment().putIfAbsent(ENV_VAULT_ADDR, vaultAddress);
                final Process process = processBuilder
                        .command(config.tokenHelper, "get")
                        .start();

                final StreamGobbler streamGobblerErr = new StreamGobbler(process.getErrorStream());
                final StreamGobbler streamGobblerOut = new StreamGobbler(process.getInputStream());

                streamGobblerErr.start();
                streamGobblerOut.start();

                if (!process.waitFor(10, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Failure running Vault Token Helper: " + config.tokenHelper + ", took too long to respond.");
                }

                streamGobblerOut.join();
                streamGobblerErr.join();

                if (streamGobblerErr.output != null && !streamGobblerErr.output.isBlank()) {
                    throw new RuntimeException("Failure running Vault Token Helper: " + config.tokenHelper + ": " + streamGobblerErr.output);
                }
                return streamGobblerOut.output;
            }
        }
        return null;
    }

    protected static class StreamGobbler extends Thread {

        private final InputStream stream;

        private String output;

        StreamGobbler(final InputStream stream) {
            this.stream = stream;
        }

        @Override
        public void run() {

            try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(stream))) {
                output = bufferedReader.lines().collect(Collectors.joining());
            } catch (IOException e) {
                throw new RuntimeException("Problem reading from Vault Token Helper: " + e.getMessage(), e);
            }
        }
    }

    protected String getUsernameKey(@NotNull DatabaseConnectionPoint point) {
        final String configured = point.getAdditionalProperty(PROP_USERNAME_KEY);
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }
        return "username";
    }

    protected String getPasswordKey(@NotNull DatabaseConnectionPoint point) {
        final String configured = point.getAdditionalProperty(PROP_PASSWORD_KEY);
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }
        return "password";
    }

    protected DynamicSecretResponse parseSecretResponse(@NotNull String body, @NotNull DatabaseConnectionPoint point) {
        JsonObject root = new Gson().fromJson(body, JsonObject.class);
        if (root == null) {
            root = new JsonObject();
        }
        final DynamicSecretResponse parsed = new DynamicSecretResponse();

        parsed.setRequestId(getAsString(root, "request_id"));
        parsed.setLeaseId(getAsString(root, "lease_id"));
        parsed.setRenewable(getAsBoolean(root, "renewable"));
        parsed.setLeaseDuration(getAsLong(root, "lease_duration"));

        final JsonObject dataObj = getAsObject(root, "data");
        final JsonObject credsObj = dataObj != null ? getAsObject(dataObj, "data") : null;

        final String usernameKey = getUsernameKey(point);
        final String passwordKey = getPasswordKey(point);

        final DynamicSecretResponse.Data credentials = new DynamicSecretResponse.Data();
        credentials.setUsername(getAsString(credsObj, usernameKey));
        credentials.setPassword(getAsString(credsObj, passwordKey));
        parsed.setData(credentials);

        return parsed;
    }

    protected void validateCredentials(@Nullable DynamicSecretResponse parsed,
                                       @NotNull DatabaseConnectionPoint point,
                                       @NotNull HttpRequest request,
                                       @Nullable String responseBody) {
        if (parsed == null || parsed.getData() == null) {
            throw new RuntimeException("Vault response didn't include the expected credentials fields. uri=" + request.uri());
        }

        final String usernameKey = getUsernameKey(point);
        final String passwordKey = getPasswordKey(point);

        if (parsed.getData().getUsername() == null || parsed.getData().getUsername().isBlank()
                || parsed.getData().getPassword() == null || parsed.getData().getPassword().isBlank()) {
            String message = "Vault secret was read but is missing/empty credentials fields. uri=" + request.uri();
            message += ". Configure the KV v2 username/password keys and ensure they exist: " +
                    "'" + usernameKey + "' and '" + passwordKey + "'.";
            throw new RuntimeException(message);
        }
    }

    private static JsonObject getAsObject(JsonObject obj, String key) {
        if (obj == null || key == null) return null;
        final JsonElement el = obj.get(key);
        return el != null && el.isJsonObject() ? el.getAsJsonObject() : null;
    }

    private static String getAsString(JsonObject obj, String key) {
        if (obj == null || key == null) return null;
        final JsonElement el = obj.get(key);
        return el != null && !el.isJsonNull() ? el.getAsString() : null;
    }

    private static Boolean getAsBoolean(JsonObject obj, String key) {
        if (obj == null || key == null) return null;
        final JsonElement el = obj.get(key);
        return el != null && !el.isJsonNull() ? el.getAsBoolean() : null;
    }

    private static Long getAsLong(JsonObject obj, String key) {
        if (obj == null || key == null) return null;
        final JsonElement el = obj.get(key);
        return el != null && !el.isJsonNull() ? el.getAsLong() : null;
    }
}
