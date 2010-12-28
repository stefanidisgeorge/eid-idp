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

package be.fedict.eid.idp.admin.webapp;

import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.IdentityService;
import be.fedict.eid.idp.model.KeyStoreType;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;
import javax.faces.model.SelectItem;
import java.util.LinkedList;
import java.util.List;

@Stateful
@Name("idpConfig")
@LocalBinding(jndiBinding = "fedict/eid/idp/admin/webapp/ConfigBean")
public class ConfigBean implements Config {

    @Logger
    private Log log;

    @EJB
    private Configuration configuration;

    @EJB
    private IdentityService identityService;

    private String xkmsUrl;
    private String xkmsTrustDomain;

    private String hmacSecret;

    private String keyStoreType;
    private String keyStorePath;
    private String keyStorePassword;
    private String keyEntryPassword;
    private String keyEntryAlias;

    private Boolean httpProxy;
    private String httpProxyHost;
    private Integer httpProxyPort;


    @Override
    @PostConstruct
    public void postConstruct() {
        this.log.debug("postConstruct");

        // XKMS Config
        this.xkmsUrl = this.configuration.getValue(ConfigProperty.XKMS_URL,
                String.class);
        this.xkmsTrustDomain = this.configuration.getValue(ConfigProperty.XKMS_TRUST_DOMAIN,
                String.class);

        // Pseudonym Config
        this.hmacSecret = this.configuration.getValue(ConfigProperty.HMAC_SECRET,
                String.class);

        // Identity Config
        this.keyStoreType =
                this.configuration.getValue(ConfigProperty.KEY_STORE_TYPE,
                        KeyStoreType.class).name();
        this.keyStorePath =
                this.configuration.getValue(ConfigProperty.KEY_STORE_PATH, String.class);
        this.keyStorePassword =
                this.configuration.getValue(ConfigProperty.KEY_STORE_SECRET, String.class);
        this.keyEntryPassword =
                this.configuration.getValue(ConfigProperty.KEY_ENTRY_SECRET, String.class);
        this.keyEntryAlias =
                this.configuration.getValue(ConfigProperty.KEY_ENTRY_ALIAS, String.class);

        // Network Config
        this.httpProxy = this.configuration.getValue(
                ConfigProperty.HTTP_PROXY_ENABLED, Boolean.class);
        this.httpProxyHost = this.configuration.getValue(
                ConfigProperty.HTTP_PROXY_HOST, String.class);
        this.httpProxyPort = this.configuration.getValue(
                ConfigProperty.HTTP_PROXY_PORT, Integer.class);
    }

    @Override
    @Remove
    @Destroy
    public void destroy() {
        this.log.debug("destroy");
    }

    @Override
    public String save() {
        this.log.debug("save");

        // XKMS Config
        this.configuration.setValue(ConfigProperty.XKMS_URL, this.xkmsUrl);
        this.configuration.setValue(ConfigProperty.XKMS_TRUST_DOMAIN,
                this.xkmsTrustDomain);

        // Pseudonym Config
        this.configuration.setValue(ConfigProperty.HMAC_SECRET,
                this.hmacSecret);

        // Identity Config
        this.configuration.setValue(ConfigProperty.KEY_STORE_TYPE,
                KeyStoreType.valueOf(this.keyStoreType));
        this.configuration.setValue(ConfigProperty.KEY_STORE_PATH,
                this.keyStorePath);
        this.configuration.setValue(ConfigProperty.KEY_STORE_SECRET,
                this.keyStorePassword);
        this.configuration.setValue(ConfigProperty.KEY_ENTRY_SECRET,
                this.keyEntryPassword);
        this.configuration.setValue(ConfigProperty.KEY_ENTRY_ALIAS,
                this.keyEntryAlias);
        this.identityService.reloadIdentity();

        // Proxy Config
        this.configuration.setValue(ConfigProperty.HTTP_PROXY_ENABLED,
                this.httpProxy);
        this.configuration.setValue(ConfigProperty.HTTP_PROXY_HOST,
                this.httpProxyHost);
        this.configuration.setValue(ConfigProperty.HTTP_PROXY_PORT,
                this.httpProxyPort);

        return null;
    }

    @Override
    @Factory("keyStoreTypes")
    public List<SelectItem> keyStoreTypeFactory() {

        List<SelectItem> keyStoreTypes = new LinkedList<SelectItem>();
        for (KeyStoreType type : KeyStoreType.values()) {
            keyStoreTypes.add(new SelectItem(type.name(), type.name()));
        }
        return keyStoreTypes;
    }

    @Override
    public String getXkmsUrl() {
        return this.xkmsUrl;
    }

    @Override
    public void setXkmsUrl(String xkmsUrl) {
        this.xkmsUrl = xkmsUrl;
    }

    @Override
    public String getXkmsTrustDomain() {
        return this.xkmsTrustDomain;
    }

    @Override
    public void setXkmsTrustDomain(String xkmsTrustDomain) {
        this.xkmsTrustDomain = xkmsTrustDomain;
    }

    @Override
    public String getHmacSecret() {
        return this.hmacSecret;
    }

    @Override
    public void setHmacSecret(String hmacSecret) {
        this.hmacSecret = hmacSecret;
    }

    @Override
    public String getKeyStoreType() {
        return keyStoreType;
    }

    @Override
    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    @Override
    public String getKeyStorePath() {
        return this.keyStorePath;
    }

    @Override
    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }

    @Override
    public String getKeyStorePassword() {
        return this.keyStorePassword;
    }

    @Override
    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    @Override
    public String getKeyEntryPassword() {
        return this.keyEntryPassword;
    }

    @Override
    public void setKeyEntryPassword(String keyEntryPassword) {
        this.keyEntryPassword = keyEntryPassword;
    }

    @Override
    public String getKeyEntryAlias() {
        return this.keyEntryAlias;
    }

    @Override
    public void setKeyEntryAlias(String keyEntryAlias) {
        this.keyEntryAlias = keyEntryAlias;
    }

    @Override
    public Boolean getHttpProxy() {
        return this.httpProxy;
    }

    @Override
    public void setHttpProxy(Boolean httpProxy) {
        this.httpProxy = httpProxy;
    }

    @Override
    public String getHttpProxyHost() {
        return this.httpProxyHost;
    }

    @Override
    public void setHttpProxyHost(String httpProxyHost) {
        this.httpProxyHost = httpProxyHost;
    }

    @Override
    public Integer getHttpProxyPort() {
        return this.httpProxyPort;
    }

    @Override
    public void setHttpProxyPort(Integer httpProxyPort) {
        this.httpProxyPort = httpProxyPort;
    }
}
