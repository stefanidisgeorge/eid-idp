package be.fedict.eid.idp.sp.saml2;

import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

public class AuthenticationResponseServiceBean implements AuthenticationResponseService, Serializable {

    private static final Log LOG = LogFactory.getLog(AuthenticationResponseServiceBean.class);

    @Override
    public void validateServiceCertificate(List<X509Certificate> certificateChain) throws SecurityException {

        LOG.debug("validate saml response cert.chain: size=" + certificateChain.size());
    }
}
