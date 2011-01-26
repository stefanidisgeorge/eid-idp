/*
 * eID Digital Signature Service Project.
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

package be.fedict.eid.idp.spi;

import java.util.GregorianCalendar;

/**
 * Enumeration of all default eID Attributes.
 *
 * @author Wim Vandenhaute
 */
public enum DefaultAttribute {

        LAST_NAME("be:fedict:eid:idp:lastname", String.class),
        FIRST_NAME("be:fedict:eid:idp:firstname", String.class),
        NAME("be:fedict:eid:idp:name", String.class),
        IDENTIFIER("be:fedict:eid:idp:identifier", String.class),
        ADDRESS("be:fedict:eid:idp:address", String.class),
        LOCALITY("be:fedict:eid:idp:locality", String.class),
        POSTAL_CODE("be:fedict:eid:idp:postalcode", String.class),
        GENDER("be:fedict:eid:idp:gender", String.class),
        DATE_OF_BIRTH("be:fedict:eid:idp:dob", GregorianCalendar.class),
        NATIONALITY("be:fedict:eid:idp:nationality", String.class),
        PLACE_OF_BIRTH("be:fedict:eid:idp:pob", String.class),
        PHOTO("be:fedict:eid:idp:photo", Byte[].class);


        private final String uri;

        private final Class<?> type;

        private DefaultAttribute(String uri, Class<?> type) {
                this.uri = uri;
                this.type = type;
        }

        public String getUri() {
                return this.uri;
        }

        public Class<?> getType() {
                return type;
        }
}
