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

package be.fedict.eid.idp.spi;

/**
 * Attribute data object returned to the authentication protocols.
 */
public class Attribute {

        private String uri;
        private final AttributeType attributeType;
        private final Object value;

        public Attribute(String uri, AttributeType attributeType,
                         Object value) {
                this.uri = uri;
                this.attributeType = attributeType;
                this.value = value;
        }

        public String getUri() {
                return this.uri;
        }

        public void setUri(String uri) {
                this.uri = uri;
        }

        public AttributeType getAttributeType() {
                return attributeType;
        }

        public Object getValue() {
                return this.value;
        }
}
