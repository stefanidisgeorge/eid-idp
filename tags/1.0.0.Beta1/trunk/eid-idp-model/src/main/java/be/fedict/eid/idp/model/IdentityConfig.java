package be.fedict.eid.idp.model;

public class IdentityConfig {

    private String name;
    private KeyStoreType keyStoreType;
    private String keyStorePath;
    private String keyStorePassword;
    private String keyEntryPassword;
    private String keyEntryAlias;

    private boolean active = false;

    public IdentityConfig(String name) {

        this.name = name;
        this.keyStoreType = KeyStoreType.PKCS12;
    }

    public IdentityConfig(String name, KeyStoreType keyStoreType, String keyStorePath,
                          String keyStorePassword, String keyEntryPassword,
                          String keyEntryAlias) {

        this.name = name;
        this.keyStoreType = keyStoreType;
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.keyEntryPassword = keyEntryPassword;
        this.keyEntryAlias = keyEntryAlias;
    }

    public KeyStoreType getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(KeyStoreType keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getKeyStorePath() {
        return keyStorePath;
    }

    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getKeyEntryPassword() {
        return keyEntryPassword;
    }

    public void setKeyEntryPassword(String keyEntryPassword) {
        this.keyEntryPassword = keyEntryPassword;
    }

    public String getKeyEntryAlias() {
        return keyEntryAlias;
    }

    public void setKeyEntryAlias(String keyEntryAlias) {
        this.keyEntryAlias = keyEntryAlias;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}
