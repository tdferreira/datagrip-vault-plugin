package com.premiumminds.datagrip.vault;

import java.util.List;

/**
 * Minimal model for Vault error responses.
 *
 * Vault often returns: {"errors":["..."]}
 * but some gateways return {"errors":[]} with no message.
 */
public class VaultErrorResponse {
    private List<String> errors;

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }
}

