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
public class Attribute<T> {

        private final String name;
        private final Class<T> type;
        private final T value;

        private String uri;

        public Attribute(String name, Class<T> type, T value, String uri) {
                this.name = name;
                this.type = type;
                this.value = value;
                this.uri = uri;
        }

        public String getName() {
                return this.name;
        }

        public Class<T> getType() {
                return this.type;
        }

        public T getValue() {
                return this.value;
        }

        public String getUri() {
                return this.uri;
        }

        public void setUri(String uri) {
                this.uri = uri;
        }
}
