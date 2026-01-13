package com.premiumminds.datagrip.vault;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;

import java.lang.reflect.Type;

public class DynamicSecretResponse {

    public static class Data {
        private String password;
        private String username;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    private String requestId;
    private String leaseId;
    private Boolean renewable;
    private Long leaseDuration;

    /** Always the decoded credentials payload {username,password} regardless of Vault engine. */
    private Data credentials;

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getLeaseId() {
        return leaseId;
    }

    public void setLeaseId(String leaseId) {
        this.leaseId = leaseId;
    }

    public Boolean getRenewable() {
        return renewable;
    }

    public void setRenewable(Boolean renewable) {
        this.renewable = renewable;
    }

    public Long getLeaseDuration() {
        return leaseDuration;
    }

    public void setLeaseDuration(Long leaseDuration) {
        this.leaseDuration = leaseDuration;
    }

    /**
     * Backwards compatible: existing code calls getData().
     * Returns the resolved credentials for both dynamic secrets and KV v2.
     */
    public Data getData() {
        return credentials;
    }

    public void setData(Data credentials) {
        this.credentials = credentials;
    }

    public Data getCredentials() {
        return credentials;
    }

    public void setCredentials(Data credentials) {
        this.credentials = credentials;
    }

    /**
     * Gson adapter to support both:
     * - dynamic secrets: data.{username,password}
     * - KV v2: data.data.{username,password}
     */
    public static final class Deserializer implements JsonDeserializer<DynamicSecretResponse> {

        @Override
        public DynamicSecretResponse deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
                throws JsonParseException {
            final JsonObject root = json != null && json.isJsonObject() ? json.getAsJsonObject() : new JsonObject();

            final DynamicSecretResponse out = new DynamicSecretResponse();

            out.requestId = getAsString(root, "request_id");
            out.leaseId = getAsString(root, "lease_id");
            out.renewable = getAsBoolean(root, "renewable");
            out.leaseDuration = getAsLong(root, "lease_duration");

            // Resolve credentials from either dynamic secret or KV v2 shapes.
            Data creds = null;
            final JsonObject dataObj = getAsObject(root, "data");
            if (dataObj != null) {
                // KV v2: data.data
                final JsonObject nested = getAsObject(dataObj, "data");
                if (nested != null && (nested.has("username") || nested.has("password"))) {
                    creds = context.deserialize(nested, Data.class);
                } else if (dataObj.has("username") || dataObj.has("password")) {
                    // Dynamic secret: data
                    creds = context.deserialize(dataObj, Data.class);
                }
            }

            out.credentials = creds;
            return out;
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
}