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

package be.fedict.eid.idp.webapp;

import be.fedict.eid.idp.entity.AttributeEntity;
import be.fedict.eid.idp.entity.RPAttributeEntity;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.model.AttributeService;
import be.fedict.eid.idp.model.Constants;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.*;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.contexts.SessionContext;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.international.LocaleSelector;
import org.jboss.seam.log.Log;

import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;
import javax.faces.context.FacesContext;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

@Stateful
@Name("idpSP")
@LocalBinding(jndiBinding = Constants.IDP_JNDI_CONTEXT + "webapp/SPBean")
public class SPBean implements SP {

        private static final String ATTRIBUTE_LIST_NAME = "idpRPAttributes";

        @Logger
        private Log log;

        @In(create = true)
        private SessionContext sessionContext;

        @In(create = true)
        FacesMessages facesMessages;

        @In
        private LocaleSelector localeSelector;

        @In(value = SP.LANGUAGE_LIST_SESSION_ATTRIBUTE, scope = ScopeType.SESSION, required = false)
        private List<String> languages;

        @EJB
        AttributeService attributeService;

        @SuppressWarnings("unused")
        @DataModel(ATTRIBUTE_LIST_NAME)
        private List<AttributeEntity> attributeList;

        @Remove
        @Destroy
        public void destroy() {
                this.log.debug("destroy");

        }

        @Override
        public String getRp() {

                RPEntity rp = (RPEntity)
                        this.sessionContext.get(Constants.RP_SESSION_ATTRIBUTE);
                if (null != rp) {
                        return rp.getName();
                }
                return null;
        }

        @Override
        @Factory(ATTRIBUTE_LIST_NAME)
        public void attributeFactory() {

                RPEntity rp = (RPEntity)
                        this.sessionContext.get(Constants.RP_SESSION_ATTRIBUTE);
                if (null != rp) {
                        this.attributeList = new LinkedList<AttributeEntity>();
                        for (RPAttributeEntity rpAttribute : rp.getAttributes()) {
                                this.attributeList.add(rpAttribute.getAttribute());
                        }
                } else {
                        this.attributeList = this.attributeService.listAttributes();
                }
        }

        @Override
        public void initLanguage() {
                this.log.debug("languages: #0", this.languages);
                if (null != this.languages) {

                        Iterator<Locale> supportedLocales =
                                FacesContext.getCurrentInstance()
                                        .getApplication().getSupportedLocales();

                        for (String language : this.languages) {

                                while (supportedLocales.hasNext()) {
                                        Locale locale = supportedLocales.next();
                                        this.log.debug("language: " + language +
                                                " supportedLocale: " + locale.getLanguage());
                                        if (locale.getLanguage().equals(language)) {
                                                // we got a winner
                                                this.localeSelector.setLocale(locale);
                                                this.localeSelector.select();
                                                return;
                                        }
                                }
                        }
                }
        }

}
