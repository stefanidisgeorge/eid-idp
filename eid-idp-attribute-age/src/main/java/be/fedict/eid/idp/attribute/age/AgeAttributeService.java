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

package be.fedict.eid.idp.attribute.age;

import be.fedict.eid.idp.spi.Attribute;
import be.fedict.eid.idp.spi.DefaultAttribute;
import be.fedict.eid.idp.spi.IdentityProviderAttributeService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.joda.time.Years;

import javax.servlet.ServletContext;
import java.util.GregorianCalendar;
import java.util.Map;

/**
 * Age Attribute service.
 *
 * @author Wim Vandenhaute
 */
public class AgeAttributeService implements IdentityProviderAttributeService {

        private static final Log LOG = LogFactory
                .getLog(AgeAttributeService.class);

        private static final String URI = "be:fedict:eid:idp:age";

        public void init(ServletContext servletContext) {
        }

        @SuppressWarnings("unchecked")
        public void addAttribute(Map<String, Attribute> attributeMap) {

                LOG.debug("Add age attribute");
                Attribute<GregorianCalendar> dobAttribute =
                        attributeMap.get(DefaultAttribute.DATE_OF_BIRTH.getUri());
                if (null != dobAttribute) {

                        DateTime dob = new DateTime(dobAttribute.getValue().getTime());
                        DateTime now = new DateTime();
                        Years years = Years.yearsBetween(dob, now);
                        int age = years.getYears();
                        attributeMap.put(URI, new Attribute<String>(URI,
                                String.class, Integer.toString(age), URI));
                }
        }
}
