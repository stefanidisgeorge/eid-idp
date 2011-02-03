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

        private String idPEntryPoint;
        private String spResponseEndpoint;

        @Override
        public String getSPDestination() {

                LOG.debug("get SP destination: " + this.spResponseEndpoint);
                return this.spResponseEndpoint;
        }

        @Override
        public String getIdPDestination() {

                LOG.debug("get IdP destionation: " + this.idPEntryPoint);
                return this.idPEntryPoint;
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


        public String getIdPEntryPoint() {
                return idPEntryPoint;
        }

        public void setIdPEntryPoint(String idPEntryPoint) {
                this.idPEntryPoint = idPEntryPoint;
        }

        public String getSpResponseEndpoint() {
                return spResponseEndpoint;
        }

        public void setSpResponseEndpoint(String spResponseEndpoint) {
                this.spResponseEndpoint = spResponseEndpoint;
        }
}
