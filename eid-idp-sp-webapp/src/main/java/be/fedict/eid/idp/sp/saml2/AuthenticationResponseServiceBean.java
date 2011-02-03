package be.fedict.eid.idp.sp.saml2;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.sp.protocol.saml2.spi.artifact.ArtifactAuthenticationResponseService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

public class AuthenticationResponseServiceBean implements ArtifactAuthenticationResponseService, Serializable {

        private static final Log LOG = LogFactory.getLog(AuthenticationResponseServiceBean.class);
        private static final long serialVersionUID = 8779248652700835953L;

        private String artifactServiceLocation;

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
        public String getArtifactServiceLocation() {

                return this.artifactServiceLocation;
        }

        public void setArtifactServiceLocation(String artifactServiceLocation) {

                this.artifactServiceLocation = artifactServiceLocation;
        }
}
