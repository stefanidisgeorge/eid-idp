/*
 * eID Identity Provider Project.
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
import be.fedict.eid.idp.model.IdentityService;
import be.fedict.eid.idp.model.KeyStoreType;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

@Stateless
public class IdentityServiceBean implements IdentityService {

    @EJB
    private IdentityServiceSingletonBean identityServiceSingletonBean;

    @EJB
    private Configuration configuration;

    /**
     * {@inheritDoc}
     */
    public byte[] getHmacSecret() {

        String secretValue =
                this.configuration.getValue(ConfigProperty.HMAC_SECRET, String.class);
        if (null == secretValue) {
            return null;
        }
        try {
            return Hex.decodeHex(secretValue.toCharArray());
        } catch (DecoderException e) {
            throw new RuntimeException("HEX decoder error: " + e.getMessage(),
                    e);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void reloadIdentity() {
        try {
            this.identityServiceSingletonBean.reloadIdentity();
        } catch (Exception e) {
            throw new EJBException("could not reload the identity: "
                    + e.getMessage(), e);
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean isIdentityConfigured() {

        return this.identityServiceSingletonBean.isIdentityConfigured();
    }

    /**
     * {@inheritDoc}
     */
    public KeyStore.PrivateKeyEntry getIdentity() {
        return this.identityServiceSingletonBean.getIdentity();
    }

    /**
     * {@inheritDoc}
     */
    public KeyStore.PrivateKeyEntry setIdentity(KeyStoreType keyStoreType,
                                                String keyStorePath,
                                                String keyStoreSecret,
                                                String keyEntrySecret,
                                                String keyEntryAlias) {

        try {
            return this.identityServiceSingletonBean.setIdentity(keyStoreType,
                    keyStorePath, keyStoreSecret, keyEntrySecret, keyEntryAlias);
        } catch (Exception e) {
            throw new EJBException("could not set the identity: "
                    + e.getMessage(), e);
        }
    }

    /**
     * {@inheritDoc}
     */
    public List<X509Certificate> getIdentityCertificateChain() {

        KeyStore.PrivateKeyEntry identity = getIdentity();
        List<X509Certificate> identityCertificateChain = new LinkedList<X509Certificate>();
        if (null == identity) {
            return identityCertificateChain;
        }
        Certificate[] certificateChain = identity.getCertificateChain();
        if (null == certificateChain) {
            return identityCertificateChain;
        }
        for (Certificate certificate : certificateChain) {
            identityCertificateChain.add((X509Certificate) certificate);
        }
        return identityCertificateChain;
    }

    /**
     * {@inheritDoc}
     */
    public String getIdentityFingerprint() {
        KeyStore.PrivateKeyEntry identity = getIdentity();
        if (null == identity) {
            return null;
        }
        X509Certificate certificate = (X509Certificate) identity
                .getCertificate();
        if (null == certificate) {
            return null;
        }
        String fingerprint;
        try {
            fingerprint = DigestUtils.shaHex(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            return null;
        }
        return fingerprint;
    }

}
