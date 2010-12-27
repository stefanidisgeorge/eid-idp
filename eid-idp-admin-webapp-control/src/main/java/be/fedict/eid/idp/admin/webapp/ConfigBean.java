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

    private String xkmsUrl;

    private String hmacSecret;

    private String keyStoreType;
    private String keyStorePath;
    private String keyStorePassword;

    @PostConstruct
    public void postConstruct() {
        this.log.debug("postConstruct");
        this.xkmsUrl = this.configuration.getValue(ConfigProperty.XKMS_URL,
                String.class);
        this.hmacSecret = this.configuration.getValue(ConfigProperty.HMAC_SECRET,
                String.class);

        this.keyStoreType =
                this.configuration.getValue(ConfigProperty.KEY_STORE_TYPE,
                        KeyStoreType.class).name();
        this.keyStorePath =
                this.configuration.getValue(ConfigProperty.KEY_STORE_PATH, String.class);
        this.keyStorePassword =
                this.configuration.getValue(ConfigProperty.KEY_STORE_SECRET, String.class);
    }

    @Remove
    @Destroy
    public void destroy() {
        this.log.debug("destroy");
    }

    public String getXkmsUrl() {
        return this.xkmsUrl;
    }

    public String save() {
        this.log.debug("save");
        this.configuration.setValue(ConfigProperty.XKMS_URL, this.xkmsUrl);
        this.configuration.setValue(ConfigProperty.HMAC_SECRET, this.hmacSecret);

        this.configuration.setValue(ConfigProperty.KEY_STORE_TYPE,
                KeyStoreType.valueOf(this.keyStoreType));
        this.configuration.setValue(ConfigProperty.KEY_STORE_PATH, this.keyStorePath);
        this.configuration.setValue(ConfigProperty.KEY_STORE_SECRET, this.keyStorePassword);

        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Factory("keyStoreTypes")
    public List<SelectItem> keyStoreTypeFactory() {

        List<SelectItem> keyStoreTypes = new LinkedList<SelectItem>();
        for (KeyStoreType type : KeyStoreType.values()) {
            keyStoreTypes.add(new SelectItem(type.name(), type.name()));
        }
        return keyStoreTypes;
    }


    public void setXkmsUrl(String xkmsUrl) {
        this.xkmsUrl = xkmsUrl;
    }

    public String getHmacSecret() {
        return this.hmacSecret;
    }

    public void setHmacSecret(String hmacSecret) {
        this.hmacSecret = hmacSecret;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
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
}
