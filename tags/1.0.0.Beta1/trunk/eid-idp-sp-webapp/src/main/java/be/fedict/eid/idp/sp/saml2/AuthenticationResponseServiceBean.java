package be.fedict.eid.idp.sp.saml2;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

public class AuthenticationResponseServiceBean implements AuthenticationResponseService, Serializable {

        private static final Log LOG = LogFactory.getLog(AuthenticationResponseServiceBean.class);

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
}
