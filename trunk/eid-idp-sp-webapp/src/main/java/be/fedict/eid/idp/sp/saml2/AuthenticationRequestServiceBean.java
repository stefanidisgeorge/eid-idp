package be.fedict.eid.idp.sp.saml2;

import be.fedict.eid.idp.sp.PkiServlet;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationRequestService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Serializable;
import java.security.KeyStore;
import java.util.Map;

public class AuthenticationRequestServiceBean implements AuthenticationRequestService, Serializable {

        private static final Log LOG = LogFactory.getLog(AuthenticationRequestServiceBean.class);
        private static final long serialVersionUID = 1185931387819658055L;

        private String endpoint;

        @Override
        public String getIdPDestination() {

                LOG.debug("get IdP destionation: " + endpoint);
                return endpoint;
        }

        @Override
        public String getRelayState(Map<String, String[]> parameterMap) {
                return null;
        }

        @Override
        public KeyStore.PrivateKeyEntry getSPIdentity() {

                LOG.debug("get SP Identity");
                try {
                        KeyStore.PrivateKeyEntry pke = PkiServlet.getPrivateKeyEntry();
                        LOG.debug("certificate: " + pke.getCertificate());
                        return pke;
                } catch (Exception e) {
                        LOG.error(e);
                        return null;
                }
        }


        public String getEndpoint() {
                return endpoint;
        }

        public void setEndpoint(String endpoint) {
                this.endpoint = endpoint;
        }
}
