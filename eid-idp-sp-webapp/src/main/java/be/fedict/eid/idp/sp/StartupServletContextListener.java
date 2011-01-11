package be.fedict.eid.idp.sp;

import be.fedict.eid.idp.sp.saml2.AuthenticationRequestServiceBean;
import be.fedict.eid.idp.sp.saml2.AuthenticationResponseServiceBean;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.*;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;


public class StartupServletContextListener implements ServletContextListener {

        private static final Log LOG = LogFactory.getLog(StartupServletContextListener.class);

        private static final String SAML2_REQUEST_BEAN_JNDI =
                "be/fedict/eid/idp/sp/saml2/AuthenticationRequestServiceBean";

        private static final String SAML2_RESPONSE_BEAN_JNDI =
                "be/fedict/eid/idp/sp/saml2/AuthenticationResponseServiceBean";

        @Override
        public void contextInitialized(ServletContextEvent sce) {

                try {
                        bindComponent(SAML2_REQUEST_BEAN_JNDI,
                                new AuthenticationRequestServiceBean());
                        bindComponent(SAML2_RESPONSE_BEAN_JNDI,
                                new AuthenticationResponseServiceBean());
                } catch (NamingException e) {
                        throw new RuntimeException(e);
                }
        }

        @Override
        public void contextDestroyed(ServletContextEvent sce) {
        }

        public static void bindComponent(String jndiName, Object component)
                throws NamingException {

                LOG.debug("bind component: " + jndiName);
                InitialContext initialContext = new InitialContext();
                String[] names = jndiName.split("/");
                Context context = initialContext;
                for (int idx = 0; idx < names.length - 1; idx++) {
                        String name = names[idx];
                        LOG.debug("name: " + name);
                        NamingEnumeration<NameClassPair> listContent = context.list("");
                        boolean subContextPresent = false;
                        while (listContent.hasMore()) {
                                NameClassPair nameClassPair = listContent.next();
                                if (!name.equals(nameClassPair.getName())) {
                                        continue;
                                }
                                subContextPresent = true;
                        }
                        if (!subContextPresent) {
                                context = context.createSubcontext(name);
                        } else {
                                context = (Context) context.lookup(name);
                        }
                }
                String name = names[names.length - 1];
                context.rebind(name, component);
        }

        public static AuthenticationRequestServiceBean getSaml2RequestBean() {

                return (AuthenticationRequestServiceBean) getComponent(SAML2_REQUEST_BEAN_JNDI);
        }


        private static Object getComponent(String jndiName) {

                try {
                        InitialContext initialContext = new InitialContext();
                        return initialContext.lookup(jndiName);
                } catch (NamingException e) {
                        throw new RuntimeException(e);
                }
        }

}
