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

package be.fedict.eid.idp.sp.wsfed;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.sp.PkiServlet;
import be.fedict.eid.idp.sp.SPBean;
import be.fedict.eid.idp.sp.protocol.ws_federation.spi.AuthenticationResponseService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public class WSFedAuthenticationResponseServiceBean implements AuthenticationResponseService, Serializable {

        private static final Log LOG = LogFactory.getLog(
                WSFedAuthenticationResponseServiceBean.class);
        private static final long serialVersionUID = -27408002115429526L;

        @Override
        public void validateServiceCertificate(SamlAuthenticationPolicy authenticationPolicy,
                                               List<X509Certificate> certificateChain)
                throws SecurityException {

                LOG.debug("validate saml response policy=" + authenticationPolicy.getUri()
                        + " cert.chain.size=" + certificateChain.size());
        }

        @Override
        public int getMaximumTimeOffset() {
                return 5;
        }

        @Override
        public SecretKey getAttributeSecretKey() {

                return SPBean.aes128SecretKey;
        }

        @Override
        public PrivateKey getAttributePrivateKey() {

                try {
                        return PkiServlet.getPrivateKeyEntry().getPrivateKey();
                } catch (Exception e) {
                        throw new RuntimeException(e);
                }
        }
}
