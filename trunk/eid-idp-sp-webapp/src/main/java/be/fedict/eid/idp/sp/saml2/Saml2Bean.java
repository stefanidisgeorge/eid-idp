package be.fedict.eid.idp.sp.saml2;

import be.fedict.eid.idp.sp.StartupServletContextListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;

public class Saml2Bean {

        private static final Log LOG = LogFactory.getLog(Saml2Bean.class);

        private HttpServletRequest request;

        public void setEndpoint(String endpoint) {

                LOG.debug("set endpoint " + endpoint + " request: " + this.request);

                StartupServletContextListener.getSaml2RequestBean().
                        setEndpoint("https://" + request.getServerName() +
                                ':' + request.getServerPort() +
                                "/eid-idp/protocol/" + endpoint);
        }

        public HttpServletRequest getRequest() {
                return request;
        }

        public void setRequest(HttpServletRequest request) {
                this.request = request;
        }
}
