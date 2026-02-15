package com.premiumminds.datagrip.vault;

import com.intellij.database.dataSource.DatabaseAuthProvider;
import com.intellij.database.dataSource.DatabaseConnectionConfig;
import com.intellij.database.dataSource.DatabaseConnectionPoint;
import com.intellij.database.dataSource.url.template.MutableParametersHolder;
import com.intellij.database.dataSource.url.template.ParametersHolder;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBTextField;
import com.intellij.uiDesigner.core.GridLayoutManager;
import org.jetbrains.annotations.NotNull;

import javax.swing.JComponent;
import javax.swing.JPanel;

import static com.premiumminds.datagrip.vault.VaultKvV2DatabaseAuthProvider.PROP_ADDRESS;
import static com.premiumminds.datagrip.vault.VaultKvV2DatabaseAuthProvider.PROP_NAMESPACE;
import static com.premiumminds.datagrip.vault.VaultKvV2DatabaseAuthProvider.PROP_PASSWORD_KEY;
import static com.premiumminds.datagrip.vault.VaultKvV2DatabaseAuthProvider.PROP_SECRET;
import static com.premiumminds.datagrip.vault.VaultKvV2DatabaseAuthProvider.PROP_TOKEN_FILE;
import static com.premiumminds.datagrip.vault.VaultKvV2DatabaseAuthProvider.PROP_USERNAME_KEY;

public class VaultKvV2Widget implements DatabaseAuthProvider.AuthWidget {

    private JPanel panel;
    private JBTextField addressText;
    private JBTextField namespaceText;
    private JBTextField secretText;
    private JBTextField tokenFileText;
    private JBTextField usernameKeyText;
    private JBTextField passwordKeyText;

    public VaultKvV2Widget() {

        final var vaultBundle = new VaultBundle();

        addressText = new JBTextField();
        namespaceText = new JBTextField();
        secretText = new JBTextField();
        tokenFileText = new JBTextField();
        usernameKeyText = new JBTextField();
        passwordKeyText = new JBTextField();

        addressText.getEmptyText().setText("e.g.: http://example.com");
        namespaceText.getEmptyText().setText("e.g.: MY_NAMESPACE");
        secretText.getEmptyText().setText("e.g.: kv/my-secret");
        tokenFileText.getEmptyText().setText("Default: $HOME/.vault-token");
        usernameKeyText.getEmptyText().setText("Default: username");
        passwordKeyText.getEmptyText().setText("Default: password");

        panel = new JPanel(new GridLayoutManager(6, 6));

        final var secretLabel = new JBLabel(vaultBundle.getMessage("secret"));
        final var addressLabel = new JBLabel(vaultBundle.getMessage("address"));
        final var namespaceLabel = new JBLabel(vaultBundle.getMessage("namespace"));
        final var tokenFileLabel = new JBLabel(vaultBundle.getMessage("tokenFile"));
        final var usernameKeyLabel = new JBLabel(vaultBundle.getMessage("usernameKey"));
        final var passwordKeyLabel = new JBLabel(vaultBundle.getMessage("passwordKey"));

        panel.add(addressLabel, VaultWidget.createLabelConstraints(0, 0, addressLabel.getPreferredSize().getWidth()));
        panel.add(addressText, VaultWidget.createSimpleConstraints(0, 1, 3));

        panel.add(namespaceLabel, VaultWidget.createLabelConstraints(1, 0, namespaceLabel.getPreferredSize().getWidth()));
        panel.add(namespaceText, VaultWidget.createSimpleConstraints(1, 1, 3));

        panel.add(secretLabel, VaultWidget.createLabelConstraints(2, 0, secretLabel.getPreferredSize().getWidth()));
        panel.add(secretText, VaultWidget.createSimpleConstraints(2, 1, 3));

        panel.add(usernameKeyLabel, VaultWidget.createLabelConstraints(3, 0, usernameKeyLabel.getPreferredSize().getWidth()));
        panel.add(usernameKeyText, VaultWidget.createSimpleConstraints(3, 1, 3));

        panel.add(passwordKeyLabel, VaultWidget.createLabelConstraints(4, 0, passwordKeyLabel.getPreferredSize().getWidth()));
        panel.add(passwordKeyText, VaultWidget.createSimpleConstraints(4, 1, 3));

        panel.add(tokenFileLabel, VaultWidget.createLabelConstraints(5, 0, tokenFileLabel.getPreferredSize().getWidth()));
        panel.add(tokenFileText, VaultWidget.createSimpleConstraints(5, 1, 3));
    }

    @Override
    public void save(@NotNull final DatabaseConnectionConfig config, final boolean copyCredentials) {
        config.setAdditionalProperty(PROP_SECRET, secretText.getText());
        config.setAdditionalProperty(PROP_ADDRESS, addressText.getText());
        config.setAdditionalProperty(PROP_NAMESPACE, namespaceText.getText());
        config.setAdditionalProperty(PROP_TOKEN_FILE, tokenFileText.getText());
        config.setAdditionalProperty(PROP_USERNAME_KEY, usernameKeyText.getText());
        config.setAdditionalProperty(PROP_PASSWORD_KEY, passwordKeyText.getText());
    }

    @Override
    public void reset(@NotNull final DatabaseConnectionPoint point, final boolean resetCredentials) {
        secretText.setText(point.getAdditionalProperty(PROP_SECRET));
        addressText.setText(point.getAdditionalProperty(PROP_ADDRESS));
        namespaceText.setText(point.getAdditionalProperty(PROP_NAMESPACE));
        tokenFileText.setText(point.getAdditionalProperty(PROP_TOKEN_FILE));
        final String usernameKey = point.getAdditionalProperty(PROP_USERNAME_KEY);
        final String passwordKey = point.getAdditionalProperty(PROP_PASSWORD_KEY);
        usernameKeyText.setText((usernameKey == null || usernameKey.isBlank()) ? "" : usernameKey);
        passwordKeyText.setText((passwordKey == null || passwordKey.isBlank()) ? "" : passwordKey);
    }

    @Override
    public void onChanged(@NotNull final Runnable runnable) {

    }

    @Override
    public boolean isPasswordChanged() {
        return false;
    }

    @Override
    public void hidePassword() {

    }

    @Override
    public void reloadCredentials() {

    }

    @Override
    public @NotNull JComponent getComponent() {
        return panel;
    }

    @Override
    public @NotNull JComponent getPreferredFocusedComponent() {
        return addressText;
    }

    @Override
    public void forceSave() {

    }

    @Override
    public void updateFromUrl(@NotNull ParametersHolder parametersHolder) {

    }

    @Override
    public void updateUrl(@NotNull MutableParametersHolder mutableParametersHolder) {

    }
}
