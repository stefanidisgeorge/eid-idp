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

package be.fedict.eid.idp.admin.webapp.bean;

import be.fedict.eid.idp.admin.webapp.Config;
import be.fedict.eid.idp.entity.AppletConfigEntity;
import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.KeyStoreType;
import org.apache.commons.io.FileUtils;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.*;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.log.Log;
import org.richfaces.event.UploadEvent;
import org.richfaces.model.UploadItem;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;
import javax.faces.model.SelectItem;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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

        @In
        FacesMessages facesMessages;

        @In(value = "selectedTab", required = false)
        @Out(value = "selectedTab", required = false, scope = ScopeType.CONVERSATION)
        private String selectedTab = null;

        @In(value = "uploadedCertificate", required = false)
        @Out(value = "uploadedCertificate", required = false, scope = ScopeType.CONVERSATION)
        private byte[] certificateBytes;

        enum ConfigurationTab {
                tab_xkms, tab_pseudonym, tab_network, tab_applet
        }

        private String xkmsUrl;
        private String xkmsAuthTrustDomain;
        private String xkmsIdentTrustDomain;

        private String hmacSecret;

        private Boolean httpProxy;
        private String httpProxyHost;
        private Integer httpProxyPort;

        private AppletConfigEntity appletConfig;


        @Override
        @PostConstruct
        public void postConstruct() {

                // XKMS Config
                this.xkmsUrl = this.configuration.getValue(ConfigProperty.XKMS_URL,
                        String.class);
                this.xkmsAuthTrustDomain =
                        this.configuration.getValue(ConfigProperty.XKMS_AUTH_TRUST_DOMAIN,
                                String.class);
                this.xkmsIdentTrustDomain =
                        this.configuration.getValue(ConfigProperty.XKMS_IDENT_TRUST_DOMAIN,
                                String.class);

                // Pseudonym Config
                this.hmacSecret = this.configuration.getValue(ConfigProperty.HMAC_SECRET,
                        String.class);

                // Network Config
                this.httpProxy = this.configuration.getValue(
                        ConfigProperty.HTTP_PROXY_ENABLED, Boolean.class);
                this.httpProxyHost = this.configuration.getValue(
                        ConfigProperty.HTTP_PROXY_HOST, String.class);
                this.httpProxyPort = this.configuration.getValue(
                        ConfigProperty.HTTP_PROXY_PORT, Integer.class);

                // Applet config
                this.appletConfig = this.configuration.getAppletConfig();
        }

        @Override
        @Remove
        @Destroy
        public void destroy() {
        }

        @Override
        public String saveXkms() {

                this.log.debug("save xkms");

                // XKMS Config
                this.configuration.setValue(ConfigProperty.XKMS_URL, this.xkmsUrl);
                this.configuration.setValue(ConfigProperty.XKMS_AUTH_TRUST_DOMAIN,
                        this.xkmsAuthTrustDomain);
                this.configuration.setValue(ConfigProperty.XKMS_IDENT_TRUST_DOMAIN,
                        this.xkmsIdentTrustDomain);

                this.selectedTab = ConfigurationTab.tab_xkms.name();

                return "success";
        }

        @Override
        public String savePseudonym() {

                this.log.debug("save pseudonym");

                // Pseudonym Config
                this.configuration.setValue(ConfigProperty.HMAC_SECRET,
                        this.hmacSecret);

                this.selectedTab = ConfigurationTab.tab_pseudonym.name();

                return "success";
        }

        @Override
        public String saveNetwork() {

                this.log.debug("save proxy");

                // Proxy Config
                this.configuration.setValue(ConfigProperty.HTTP_PROXY_ENABLED,
                        this.httpProxy);
                this.configuration.setValue(ConfigProperty.HTTP_PROXY_HOST,
                        this.httpProxyHost);
                this.configuration.setValue(ConfigProperty.HTTP_PROXY_PORT,
                        this.httpProxyPort);

                this.selectedTab = ConfigurationTab.tab_network.name();

                return "success";
        }

        @Override
        @End
        public String saveApplet() {

                this.log.debug("save applet config");

                // Applet config
                try {
                        this.appletConfig.setServerCertificate(
                                getCertificate(this.certificateBytes));
                } catch (CertificateException e) {
                        this.log.error("Certificate exception: " + e.getMessage(), e);
                        this.facesMessages.addToControl("upload", "Invalid certificate");
                        return null;
                }

                this.configuration.setAppletConfig(this.appletConfig);

                this.selectedTab = ConfigurationTab.tab_applet.name();
                return "success";
        }

        @Override
        public String removeApplet() {

                this.log.debug("remove applet config");
                this.configuration.removeAppletConfig(this.appletConfig);
                this.appletConfig = new AppletConfigEntity();

                this.selectedTab = ConfigurationTab.tab_applet.name();
                return "success";
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
        public String getXkmsAuthTrustDomain() {
                return this.xkmsAuthTrustDomain;
        }

        @Override
        public void setXkmsAuthTrustDomain(String xkmsAuthTrustDomain) {
                this.xkmsAuthTrustDomain = xkmsAuthTrustDomain;
        }

        @Override
        public String getXkmsIdentTrustDomain() {
                return this.xkmsIdentTrustDomain;
        }

        @Override
        public void setXkmsIdentTrustDomain(String xkmsIdentTrustDomain) {
                this.xkmsIdentTrustDomain = xkmsIdentTrustDomain;
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

        @Override
        public AppletConfigEntity getAppletConfig() {
                return this.appletConfig;
        }

        @Override
        public void setAppletConfig(AppletConfigEntity appletConfig) {
                this.appletConfig = appletConfig;
        }

        @Override
        public String getSelectedTab() {
                return this.selectedTab;
        }

        @Override
        public void setSelectedTab(String selectedTab) {
                this.selectedTab = selectedTab;
        }

        @Override
        @Begin(join = true)
        public void uploadListener(UploadEvent event) throws IOException {

                UploadItem item = event.getUploadItem();
                this.log.debug(item.getContentType());
                this.log.debug(item.getFileSize());
                this.log.debug(item.getFileName());
                if (null == item.getData()) {
                        // meaning createTempFiles is set to true in the SeamFilter
                        this.certificateBytes = FileUtils.readFileToByteArray(item
                                .getFile());
                } else {
                        this.certificateBytes = item.getData();
                }
        }

        private X509Certificate getCertificate(byte[] certificateBytes)
                throws CertificateException {

                CertificateFactory certificateFactory = CertificateFactory
                        .getInstance("X.509");
                return (X509Certificate) certificateFactory
                        .generateCertificate(new ByteArrayInputStream(certificateBytes));
        }
}
