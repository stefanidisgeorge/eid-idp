/*
 * eID Digital Signature Service Project.
 * Copyright (C) 2010 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package be.fedict.eid.idp.model.bean;

import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.IdentityConfig;
import be.fedict.eid.idp.model.KeyStoreType;
import be.fedict.eid.idp.model.exception.KeyStoreLoadException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import sun.security.pkcs11.SunPKCS11;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.util.Enumeration;

@Singleton
@Startup
public class IdentityServiceSingletonBean {

    private static final Log LOG = LogFactory
            .getLog(IdentityServiceSingletonBean.class);

    private PrivateKeyEntry identity;

    @EJB
    private Configuration configuration;

    /**
     * @return if an active identity is configured
     */
    public boolean isIdentityConfigured() {
        return null != this.configuration.getValue(ConfigProperty.ACTIVE_IDENTITY,
                String.class);
    }

    /**
     * Set new active identity
     *
     * @param name new active identity's name
     * @throws KeyStoreLoadException failed to load keystore
     */
    public void setActiveIdentity(String name) throws KeyStoreLoadException {

        LOG.debug("set active identity: " + name);
        IdentityConfig identityConfig = findIdentityConfig(name);

        if (null == identityConfig) {
            throw new KeyStoreLoadException("Identity config \"" + name + "\" not found!");
        }

        this.configuration.setValue(ConfigProperty.ACTIVE_IDENTITY, name);

        this.identity = loadIdentity(identityConfig);
        LOG.debug("private key entry reloaded");
    }

    /**
     * Reload current active identity
     *
     * @throws KeyStoreLoadException failed to load keystore
     */
    public void reloadIdentity() throws KeyStoreLoadException {

        String activeIdentity =
                this.configuration.getValue(ConfigProperty.ACTIVE_IDENTITY,
                        String.class);

        if (null == activeIdentity) {
            throw new KeyStoreLoadException("No active identity set!");
        }

        this.identity = loadIdentity(activeIdentity);
        LOG.debug("private key entry reloaded");
    }

    /**
     * Load identity keystore with specified name
     *
     * @param name identity name
     * @return private key entry of identity
     * @throws KeyStoreLoadException failed to load keystore
     */
    public PrivateKeyEntry loadIdentity(String name)
            throws KeyStoreLoadException {

        IdentityConfig identityConfig = findIdentityConfig(name);
        return loadIdentity(identityConfig);
    }

    /**
     * Load identity keystore
     *
     * @param identityConfig identity configuration
     * @return private key entry of identity
     * @throws KeyStoreLoadException failed to load keystore
     */
    public PrivateKeyEntry loadIdentity(IdentityConfig identityConfig)
            throws KeyStoreLoadException {

        try {

            if (null == identityConfig) {
                throw new KeyStoreLoadException("Identity config is empty!");
            }

            FileInputStream keyStoreInputStream = null;
            if (identityConfig.getKeyStoreType().equals(KeyStoreType.PKCS11)) {
                Security.addProvider(new SunPKCS11(identityConfig.getKeyStorePath()));
            } else {
                try {
                    keyStoreInputStream = new FileInputStream(identityConfig.getKeyStorePath());
                } catch (FileNotFoundException e) {
                    throw new KeyStoreLoadException(
                            "Can't load keystore from config-specified location: "
                                    + identityConfig.getKeyStorePath(), e);
                }
            }


            // load keystore
            KeyStore keyStore = KeyStore.getInstance(identityConfig.getKeyStoreType()
                    .getJavaKeyStoreType());
            char[] password;
            if (null != identityConfig.getKeyStorePassword() &&
                    !identityConfig.getKeyStorePassword().isEmpty()) {
                password = identityConfig.getKeyStorePassword().toCharArray();
            } else {
                password = null;
            }
            keyStore.load(keyStoreInputStream, password);


            // find entry alias
            Enumeration<String> aliases = keyStore.aliases();
            if (!aliases.hasMoreElements()) {
                throw new KeyStoreLoadException("no keystore aliases present");
            }

            String alias;
            if (null != identityConfig.getKeyEntryAlias() &&
                    !identityConfig.getKeyEntryAlias().trim().isEmpty()) {
                boolean found = false;
                while (aliases.hasMoreElements()) {
                    if (aliases.nextElement().equals(identityConfig.getKeyEntryAlias())) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    throw new KeyStoreLoadException("no keystore entry with alias \"" +
                            identityConfig.getKeyEntryAlias() + "\"");
                }
                alias = identityConfig.getKeyEntryAlias();
            } else {
                alias = aliases.nextElement();
            }
            LOG.debug("keystore alias: " + alias);

            // get keystore entry
            char[] entryPassword;
            if (null != identityConfig.getKeyEntryPassword() &&
                    !identityConfig.getKeyEntryPassword().isEmpty()) {
                entryPassword = identityConfig.getKeyEntryPassword().toCharArray();
            } else {
                entryPassword = null;
            }

            KeyStore.Entry entry = keyStore.getEntry(alias,
                    new KeyStore.PasswordProtection(entryPassword));
            if (!(entry instanceof PrivateKeyEntry)) {
                throw new KeyStoreLoadException("private key entry expected");
            }
            return (PrivateKeyEntry) entry;
        } catch (KeyStoreException e) {
            throw new KeyStoreLoadException(e);
        } catch (CertificateException e) {
            throw new KeyStoreLoadException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreLoadException(e);
        } catch (UnrecoverableEntryException e) {
            throw new KeyStoreLoadException(e);
        } catch (IOException e) {
            throw new KeyStoreLoadException(e);
        }
    }

    /**
     * @return current identity's private key entry
     */
    public PrivateKeyEntry getIdentity() {

        return this.identity;
    }

    /**
     * @return current identity's configuration
     */
    public IdentityConfig getIdentityConfig() {

        String activeIdentity =
                this.configuration.getValue(ConfigProperty.ACTIVE_IDENTITY,
                        String.class);

        if (null == activeIdentity) {
            throw new EJBException("No active identity set!");
        }

        IdentityConfig identityConfig = findIdentityConfig(activeIdentity);
        if (null == identityConfig) {
            throw new EJBException("No active identity config found!");
        }
        return identityConfig;
    }

    /**
     * @param name identity name
     * @return identity config or <code>null</code> if not found.
     */
    public IdentityConfig findIdentityConfig(String name) {

        KeyStoreType keyStoreType = this.configuration.getValue(
                ConfigProperty.KEY_STORE_TYPE, name, KeyStoreType.class);
        if (null == keyStoreType) {
            return null;
        }
        String keyStorePath = this.configuration.getValue(
                ConfigProperty.KEY_STORE_PATH, name, String.class);
        String keyStoreSecret = this.configuration.getValue(
                ConfigProperty.KEY_STORE_SECRET, name, String.class);
        String keyEntrySecret = this.configuration.getValue(
                ConfigProperty.KEY_ENTRY_SECRET, name, String.class);
        String keyEntryAlias = this.configuration.getValue(
                ConfigProperty.KEY_ENTRY_ALIAS, name, String.class);

        return new IdentityConfig(name, keyStoreType, keyStorePath,
                keyStoreSecret, keyEntrySecret, keyEntryAlias);
    }

    /**
     * Add/update identity from specified configuration
     *
     * @param identityConfig identity configuration
     * @return private key entry of identity
     * @throws KeyStoreLoadException failed to load keystore
     */
    public PrivateKeyEntry setIdentity(IdentityConfig identityConfig)
            throws KeyStoreLoadException {

        this.configuration.setValue(ConfigProperty.KEY_STORE_TYPE,
                identityConfig.getName(), identityConfig.getKeyStoreType());
        this.configuration.setValue(ConfigProperty.KEY_STORE_PATH,
                identityConfig.getName(), identityConfig.getKeyStorePath());
        this.configuration.setValue(ConfigProperty.KEY_STORE_SECRET,
                identityConfig.getName(), identityConfig.getKeyStorePassword());
        this.configuration.setValue(ConfigProperty.KEY_ENTRY_SECRET,
                identityConfig.getName(), identityConfig.getKeyEntryPassword());
        if (null != identityConfig.getKeyEntryAlias()) {
            this.configuration.setValue(ConfigProperty.KEY_ENTRY_ALIAS,
                    identityConfig.getName(), identityConfig.getKeyEntryAlias());
        }

        return loadIdentity(identityConfig.getName());
    }
}
