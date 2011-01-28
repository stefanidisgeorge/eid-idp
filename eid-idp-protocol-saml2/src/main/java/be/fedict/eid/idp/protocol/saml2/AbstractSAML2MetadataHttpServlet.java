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

package be.fedict.eid.idp.protocol.saml2;

import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.spi.IdPIdentity;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderConfigurationFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.w3c.dom.Element;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

public abstract class AbstractSAML2MetadataHttpServlet extends HttpServlet {

        private static final long serialVersionUID = 3945029803660891205L;

        private static final Log LOG = LogFactory
                .getLog(AbstractSAML2MetadataHttpServlet.class);

        static {
                /*
                * Next is because Sun loves to endorse crippled versions of Xerces.
                */
                System.setProperty("javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema",
                        "org.apache.xerces.jaxp.validation.XMLSchemaFactory");
                try {
                        DefaultBootstrap.bootstrap();
                } catch (ConfigurationException e) {
                        throw new RuntimeException("could not bootstrap the OpenSAML2 library", e);
                }
        }

        @Override
        protected void doGet(HttpServletRequest request,
                             HttpServletResponse response) throws ServletException, IOException {
                LOG.debug("doGet");
                response.setContentType("application/samlmetadata+xml; charset=UTF-8");

                IdentityProviderConfiguration configuration = IdentityProviderConfigurationFactory
                        .getInstance(request);

                OutputStream outputStream = response.getOutputStream();
                try {
                        writeMetadata(request, configuration, outputStream);
                } catch (Exception e) {
                        throw new ServletException("error: " + e.getMessage(), e);
                }
        }

        private void writeMetadata(HttpServletRequest request,
                                   IdentityProviderConfiguration configuration,
                                   OutputStream outputStream)

                throws ServletException, TransformerException, IOException {

                String location = "https://" + request.getServerName() + ":"
                        + request.getServerPort() + request.getContextPath()
                        + "/protocol/" + getPath();
                LOG.debug("location: " + location);

                // Add a descriptor for our node (the SAMLv2 Entity).
                EntityDescriptor entityDescriptor =
                        Saml2Util.buildXMLObject(EntityDescriptor.class,
                                EntityDescriptor.DEFAULT_ELEMENT_NAME);

                entityDescriptor.setEntityID(location);

                // signature
                IdPIdentity identity = configuration.findIdentity();
                if (null != identity) {
                        // Add a signature to the entity descriptor.
                        Signature signature = Saml2Util.buildXMLObject(Signature.class,
                                Signature.DEFAULT_ELEMENT_NAME);
                        entityDescriptor.setSignature(signature);

                        signature.setCanonicalizationAlgorithm(
                                SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

                        // add certificate chain as keyinfo
                        signature.setKeyInfo(getKeyInfo(identity.getPrivateKeyEntry()));

                        BasicX509Credential signingCredential = new BasicX509Credential();
                        signingCredential.setPrivateKey(identity.getPrivateKeyEntry().
                                getPrivateKey());
                        signingCredential.setEntityCertificateChain(
                                getCertificateChain(identity.getPrivateKeyEntry()));
                        signature.setSigningCredential(signingCredential);

                        String algorithm = identity.getPrivateKeyEntry()
                                .getPrivateKey().getAlgorithm();
                        if ("RSA".equals(algorithm)) {
                                signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
                        } else {
                                signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1);
                        }
                }

                // Add a descriptor for our identity services.
                IDPSSODescriptor idpSsoDescriptor =
                        Saml2Util.buildXMLObject(IDPSSODescriptor.class,
                                IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
                entityDescriptor.getRoleDescriptors().add(idpSsoDescriptor);

                idpSsoDescriptor.setWantAuthnRequestsSigned(false);
                idpSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

                if (null != identity) {
                        KeyDescriptor keyDescriptor =
                                Saml2Util.buildXMLObject(KeyDescriptor.class,
                                        KeyDescriptor.DEFAULT_ELEMENT_NAME);
                        keyDescriptor.setKeyInfo(getKeyInfo(identity.getPrivateKeyEntry()));
                        idpSsoDescriptor.getKeyDescriptors().add(keyDescriptor);
                }

                // Add a descriptor for the authentication service (HTTP-POST).
                SingleSignOnService ssoServicePost = Saml2Util.buildXMLObject(
                        SingleSignOnService.class,
                        SingleSignOnService.DEFAULT_ELEMENT_NAME);
                idpSsoDescriptor.getSingleSignOnServices().add(ssoServicePost);

                ssoServicePost.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
                ssoServicePost.setLocation(location);

                // Marshall & sign the entity descriptor.
                Element element;
                if (null != identity) {

                        LOG.debug("sign SAML2 Metadata");
                        element = Saml2Util.signAsElement(entityDescriptor, entityDescriptor,
                                (X509Certificate) identity.getPrivateKeyEntry().
                                        getCertificate(),
                                identity.getPrivateKeyEntry().getPrivateKey());
                } else {

                        LOG.warn("SAML2 Metadata NOT signed!");
                        element = Saml2Util.marshall(entityDescriptor);
                }

                Saml2Util.writeDocument(element.getOwnerDocument(), outputStream);
        }

        private KeyInfo getKeyInfo(KeyStore.PrivateKeyEntry identity) {

                List<X509Certificate> certificateChain = getCertificateChain(identity);
                KeyInfo keyInfo = Saml2Util.buildXMLObject(KeyInfo.class,
                        KeyInfo.DEFAULT_ELEMENT_NAME);
                try {
                        for (X509Certificate certificate : certificateChain) {
                                KeyInfoHelper.addCertificate(keyInfo, certificate);
                        }
                } catch (CertificateEncodingException e) {
                        throw new RuntimeException("opensaml2 certificate encoding error: " + e.getMessage(), e);
                }
                return keyInfo;
        }

        private List<X509Certificate> getCertificateChain(KeyStore.PrivateKeyEntry identity) {

                List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
                for (java.security.cert.Certificate certificate : identity.getCertificateChain()) {
                        certificateChain.add((X509Certificate) certificate);
                }
                return certificateChain;
        }

        protected abstract String getPath();
}
