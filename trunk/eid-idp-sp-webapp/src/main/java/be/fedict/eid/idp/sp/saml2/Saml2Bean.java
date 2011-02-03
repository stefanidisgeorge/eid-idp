package be.fedict.eid.idp.sp.saml2;

import be.fedict.eid.idp.sp.StartupServletContextListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;

public class Saml2Bean {

        private static final Log LOG = LogFactory.getLog(Saml2Bean.class);

        private HttpServletRequest request;

        public void setIdPEntryPoint(String idPEntryPoint) {

                LOG.debug("set IdP Entry Point " + idPEntryPoint);

                StartupServletContextListener.getSaml2RequestBean().
                        setIdPEntryPoint("https://" + this.request.getServerName() +
                                ':' + this.request.getServerPort() +
                                "/eid-idp/protocol/" + idPEntryPoint);
        }

        public void setSpResponseEndpoint(String spResponseEndpoint) {

                LOG.debug("set SP Response Endpoint: " + spResponseEndpoint);

                StartupServletContextListener.getSaml2RequestBean().
                        setSpResponseEndpoint(this.request.getScheme() + "://"
                                + this.request.getServerName() + ":"
                                + this.request.getServerPort()
                                + this.request.getContextPath() + "/"
                                + spResponseEndpoint);
        }

        public void setArtifactServiceEndpoint(String notUsed) {

                LOG.debug("set SAML2 Artifact Service endpoint");

//                TODO: SSL ...
//                StartupServletContextListener.getSaml2ResponseBean().
//                        setArtifactServiceLocation("http://" +
//                                this.request.getServerName() + ":8080" +
//                                "/eid-idp/ws/saml2/artifact");
                StartupServletContextListener.getSaml2ResponseBean().
                        setArtifactServiceLocation("https://" +
                                this.request.getServerName() + ':' +
                                this.request.getServerPort() +
                                "/eid-idp/ws/saml2/artifact");
        }


        public HttpServletRequest getRequest() {
                return request;
        }

        public void setRequest(HttpServletRequest request) {
                this.request = request;
        }
}
