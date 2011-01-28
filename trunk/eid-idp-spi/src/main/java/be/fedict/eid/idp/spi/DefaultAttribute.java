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

/**
 * Enumeration of all default eID Attributes.
 *
 * @author Wim Vandenhaute
 */
public enum DefaultAttribute {

        LAST_NAME("be:fedict:eid:idp:lastname", AttributeType.STRING),
        FIRST_NAME("be:fedict:eid:idp:firstname", AttributeType.STRING),
        NAME("be:fedict:eid:idp:name", AttributeType.STRING),
        IDENTIFIER("be:fedict:eid:idp:identifier", AttributeType.STRING),
        ADDRESS("be:fedict:eid:idp:address", AttributeType.STRING),
        LOCALITY("be:fedict:eid:idp:locality", AttributeType.STRING),
        POSTAL_CODE("be:fedict:eid:idp:postalcode", AttributeType.STRING),
        GENDER("be:fedict:eid:idp:gender", AttributeType.STRING),
        DATE_OF_BIRTH("be:fedict:eid:idp:dob", AttributeType.DATE),
        NATIONALITY("be:fedict:eid:idp:nationality", AttributeType.STRING),
        PLACE_OF_BIRTH("be:fedict:eid:idp:pob", AttributeType.STRING),
        PHOTO("be:fedict:eid:idp:photo", AttributeType.BINARY);


        private final String uri;
        private final AttributeType attributeType;

        private DefaultAttribute(String uri, AttributeType attributeType) {
                this.uri = uri;
                this.attributeType = attributeType;
        }

        public String getUri() {
                return this.uri;
        }

        public AttributeType getAttributeType() {
                return this.attributeType;
        }

        public static DefaultAttribute findDefaultAttribute(String uri) {

                for (DefaultAttribute defaultAttribute : values()) {
                        if (defaultAttribute.getUri().equals(uri)) {
                                return defaultAttribute;
                        }
                }
                return null;
        }
}
