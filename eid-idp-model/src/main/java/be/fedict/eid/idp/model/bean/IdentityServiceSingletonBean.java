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
import be.fedict.eid.idp.model.KeyStoreType;
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

    public boolean isIdentityConfigured() {
        return null != this.configuration.getValue(ConfigProperty.KEY_STORE_PATH, String.class);
    }

    public void reloadIdentity() throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableEntryException {

        KeyStoreType keyStoreType = this.configuration.getValue(
                ConfigProperty.KEY_STORE_TYPE, KeyStoreType.class);
        String keyStorePath = this.configuration.getValue(
                ConfigProperty.KEY_STORE_PATH, String.class);
        String keyStoreSecret = this.configuration.getValue(
                ConfigProperty.KEY_STORE_SECRET, String.class);

        if (null == keyStoreType) {
            this.identity = null;
            return;
        }
        if (null == keyStorePath || keyStorePath.isEmpty()) {
            this.identity = null;
            return;
        }

        FileInputStream keyStoreInputStream = null;
        if (keyStoreType.equals(KeyStoreType.PKCS11)) {
            Security.addProvider(new SunPKCS11(keyStorePath));
        } else {
            try {
                keyStoreInputStream = new FileInputStream(keyStorePath);
            } catch (FileNotFoundException e) {
                throw new EJBException(
                        "Can't load keystore from config-specified location: "
                                + keyStorePath, e);
            }
        }


        KeyStore keyStore = KeyStore.getInstance(keyStoreType
                .getJavaKeyStoreType());
        char[] password;
        if (null != keyStoreSecret && !keyStoreSecret.isEmpty()) {
            password = keyStoreSecret.toCharArray();
        } else {
            password = null;
        }
        keyStore.load(keyStoreInputStream, password);
        Enumeration<String> aliases = keyStore.aliases();
        if (!aliases.hasMoreElements()) {
            throw new EJBException("no keystore aliases present");
        }
        String alias = aliases.nextElement();
        LOG.debug("keystore alias: " + alias);
        KeyStore.Entry entry = keyStore.getEntry(alias,
                new KeyStore.PasswordProtection(password));
        if (!(entry instanceof PrivateKeyEntry)) {
            throw new EJBException("private key entry expected");
        }
        this.identity = (PrivateKeyEntry) entry;
        LOG.debug("private key entry reloaded");
    }

    public PrivateKeyEntry getIdentity() {

        return this.identity;
    }

    public PrivateKeyEntry setIdentity(KeyStoreType keyStoreType,
                                       String keyStorePath,
                                       String keyStoreSecret)
            throws IOException, NoSuchAlgorithmException,
            UnrecoverableEntryException, KeyStoreException, CertificateException {

        this.configuration.setValue(ConfigProperty.KEY_STORE_TYPE, keyStoreType);
        this.configuration.setValue(ConfigProperty.KEY_STORE_PATH, keyStorePath);
        this.configuration.setValue(ConfigProperty.KEY_STORE_SECRET, keyStoreSecret);

        reloadIdentity();

        return getIdentity();
    }
}
