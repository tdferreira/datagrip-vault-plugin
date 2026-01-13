package com.premiumminds.datagrip.vault;

import java.io.*;
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
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.intellij.database.access.DatabaseCredentials;
import com.intellij.database.dataSource.DatabaseAuthProvider;
import com.intellij.database.dataSource.DatabaseConnectionConfig;
import com.intellij.database.dataSource.DatabaseConnectionPoint;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.NonNls;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class VaultDatabaseAuthProvider implements DatabaseAuthProvider {

    private static final Logger logger = Logger.getInstance(VaultDatabaseAuthProvider.class);

    public static final String PROP_SECRET = "vault_secret";
    public static final String PROP_ADDRESS = "vault_address";
    public static final String PROP_NAMESPACE = "vault_namespace";
    public static final String PROP_TOKEN_FILE = "vault_token_file";

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

    private static final Map<DynamicSecretKey, DynamicSecretResponse> secretsCache = new ConcurrentHashMap<>();

    @Override
    public @NonNls @NotNull String getId() {
        return "vault";
    }

    @Override
    public @Nls @NotNull String getDisplayName() {
        return "Vault";
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
            if (Objects.nonNull(namespace)) logger.info("Namespace used: " + namespace);

            DynamicSecretKey key = new DynamicSecretKey(address, secret);
            DynamicSecretResponse value = secretsCache.get(key);

            if (value == null) {
                final var response = getCredentialsFromVault(protoConnection, address, namespace, secret);
                value = response;
                secretsCache.put(key, value);
            } else {
                final var lease = getLeaseFromVault(protoConnection, address, namespace, value.getLeaseId());
                if (!lease.isPresent()) {

                    final var response = getCredentialsFromVault(protoConnection, address, namespace, secret);

                    value = response;
                    secretsCache.put(key, value);
                }
            }

            logger.info("Username used " + value.getData().getUsername());

            protoConnection.getConnectionProperties().put("user", value.getData().getUsername());
            protoConnection.getConnectionProperties().put("password", value.getData().getPassword());

        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Problem connecting to Vault: " + e.getMessage(), e);
        }

        return CompletableFuture.completedFuture(protoConnection);
    }

    @Override
    public @Nullable AuthWidget createWidget(@Nullable Project project, @NotNull DatabaseCredentials credentials, @NotNull DatabaseConnectionConfig config) {
        return new VaultWidget();
    }


    private DynamicSecretResponse getCredentialsFromVault(
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
            throw new RuntimeException("Problem connecting to Vault: " + response.body());
        }

        final var gson = new GsonBuilder()
                .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                .registerTypeAdapter(DynamicSecretResponse.class, new DynamicSecretResponse.Deserializer())
                .create();

        final var parsed = gson.fromJson(response.body(), DynamicSecretResponse.class);
        if (parsed == null || parsed.getData() == null) {
            throw new RuntimeException("Vault response didn't include credentials fields (username/password). Response was: " + response.body());
        }

        return parsed;
    }

    private Optional<LeaseResponse> getLeaseFromVault(
            ProtoConnection protoConnection,
            final String address,
            final String namespace,
            final String leaseId)
            throws IOException, InterruptedException {
        final var token = getToken(protoConnection, address);

        final var uri = URI.create(address).resolve("/v1/sys/leases/lookup");

        final var gson = new GsonBuilder()
                .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                .create();

        final var leaseRequest = new LeaseRequest();
        leaseRequest.setLeaseId(leaseId);

        final var bodyJson = gson.toJson(leaseRequest);

        final var builder = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(bodyJson))
                .uri(uri)
                .header(HEADER_VAULT_TOKEN, token);

        if (namespace != null && !namespace.isBlank()) {
            builder.header(HEADER_VAULT_NAMESPACE, namespace.trim());
        }

        final var request = builder.build();

        logVaultRequest(request, bodyJson);

        final var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        logVaultResponse(response);

        if (response.statusCode() != HttpURLConnection.HTTP_OK) {
            logger.info("No lease found for " + leaseId);
            return Optional.empty();
        }

        return Optional.of(gson.fromJson(response.body(), LeaseResponse.class));
    }

    private static URI buildVaultReadUri(String address, String secret) {
        // The plugin expects `vault_secret` to be a Vault *path* like:
        // - database/creds/role (dynamic DB creds)  -> KV rewrite NOT needed
        // - kv/my/secret (KV v1)                   -> /v1/kv/my/secret
        // - kv/my/secret (KV v2)                   -> /v1/kv/data/my/secret (rewrite needed)
        // Users frequently point to a KV v2 mount without the required /data/ segment.
        final String normalizedSecret = normalizeKvV2PathIfNeeded(secret);
        return URI.create(address).resolve("/v1/").resolve(normalizedSecret);
    }

    private static String normalizeKvV2PathIfNeeded(String secret) {
        if (secret == null) return null;

        // Trim leading slashes so URI.resolve behaves predictably.
        String s = secret.trim();
        while (s.startsWith("/")) s = s.substring(1);

        // If user already specified KV v2 endpoints, don't touch.
        if (s.contains("/data/") || s.contains("/metadata/")) {
            return s;
        }

        // Heuristic: rewrite `mount/path...` -> `mount/data/path...`.
        // This fixes the common Vault warning:
        // "Invalid path for a versioned K/V secrets engine... use 'vault kv get'"
        final int firstSlash = s.indexOf('/');
        if (firstSlash <= 0 || firstSlash >= s.length() - 1) {
            return s;
        }

        final String mount = s.substring(0, firstSlash);
        final String rest = s.substring(firstSlash + 1);
        return mount + "/data/" + rest;
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

        logger.debug("Vault HTTP response: status=" + response.statusCode() +
                ", headers=" + response.headers().map() +
                ", body=" + response.body());
    }

    private String getAddress(ProtoConnection protoConnection) {
        final var definedAddress = protoConnection.getConnectionPoint().getAdditionalProperty(PROP_ADDRESS);
        if (definedAddress != null && !definedAddress.isBlank()) {
            return definedAddress;
        } else {
            final String vaultAgentAddrEnv = System.getenv(ENV_VAULT_AGENT_ADDR);
            if (vaultAgentAddrEnv != null && !vaultAgentAddrEnv.isBlank()) {
                return vaultAgentAddrEnv;
            }
            final String vaultAddrEnv = System.getenv(ENV_VAULT_ADDR);
            if (vaultAddrEnv != null && !vaultAddrEnv.isBlank()) {
                return vaultAddrEnv;
            }
        }
        throw new RuntimeException(ERROR_VAULT_ADDRESS_NOT_DEFINED);
    }

    private String getNamespace(ProtoConnection protoConnection) throws IOException {
        final var definedNamespace = protoConnection.getConnectionPoint().getAdditionalProperty(PROP_NAMESPACE);
        if (definedNamespace != null && !definedNamespace.isBlank()) {
            return definedNamespace;
        } else {
            final String vaultNamespaceEnv = System.getenv(ENV_VAULT_NAMESPACE);
            if (vaultNamespaceEnv != null && !vaultNamespaceEnv.isBlank()) {
                return vaultNamespaceEnv;
            } else {
                final var vaultConfigFile = getConfigFile();
                if (vaultConfigFile.toFile().exists()) {
                    final Gson gson = new Gson();
                    try (FileReader fileReader = new FileReader(vaultConfigFile.toFile())) {
                        final VaultConfig config = gson.fromJson(fileReader, VaultConfig.class);
                        if (config.namespace != null && !config.namespace.isBlank()) {
                            return config.namespace;
                        }
                    }
                }
            }
        }
        return null;
    }

    private String getSecret(ProtoConnection protoConnection) {
        final var secret = protoConnection.getConnectionPoint().getAdditionalProperty(PROP_SECRET);
        if (secret != null && !secret.isBlank()) {
            return secret;
        }
        throw new RuntimeException(ERROR_VAULT_SECRET_NOT_DEFINED);
    }


    private String getToken(ProtoConnection protoConnection, String vaultAddress) throws IOException, InterruptedException {

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

    private Path getConfigFile() {
        Path vaultConfigPath = Paths.get(System.getProperty("user.home"), DEFAULT_VAULT_CONFIG_FILE);

        final String vaultConfigPathEnv = System.getenv(ENV_VAULT_CONFIG_PATH);
        if (vaultConfigPathEnv != null && !vaultConfigPathEnv.isBlank()) {
            vaultConfigPath = Paths.get(vaultConfigPathEnv);
        }

        return vaultConfigPath;
    }

    private String getTokenFromVaultTokenHelper(Path configFile, String vaultAddress)
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

    private static class StreamGobbler extends Thread {

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
}
