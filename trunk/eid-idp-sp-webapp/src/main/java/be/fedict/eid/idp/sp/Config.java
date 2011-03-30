package be.fedict.eid.idp.sp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Config {

        private static final Log LOG = LogFactory.getLog(Config.class);

        public boolean isEncrypt() {
                LOG.debug("encrypt: " + PkiServlet.isEncrypt());
                return PkiServlet.isEncrypt();
        }

        public void setEncrypt(boolean encrypt) {
                LOG.debug("set encrypt: " + encrypt);
                PkiServlet.setEncrypt(encrypt);
        }

        public boolean isUseKeK() {
                LOG.debug("useKeK: " + PkiServlet.isUseKeK());
                return PkiServlet.isUseKeK();
        }

        public void setUseKeK(boolean useKeK) {
                LOG.debug("set useKeK: " + useKeK);
                PkiServlet.setUseKeK(useKeK);
        }
}
