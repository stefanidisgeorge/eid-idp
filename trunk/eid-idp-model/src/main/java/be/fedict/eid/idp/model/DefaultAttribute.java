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

package be.fedict.eid.idp.model;

/**
 * Enumeration of all default eID Attributes.
 *
 * @author Wim Vandenhaute
 */
public enum DefaultAttribute {

        LAST_NAME("Last Name"),
        FIRST_NAME("First Name"),
        NAME("Name"),
        IDENTIFIER("Identifier"),
        ADDRESS("Address"),
        LOCALITY("Locality"),
        POSTAL_CODE("Postal Code"),
        GENDER("Gender"),
        DATE_OF_BIRTH("Date Of Birth"),
        NATIONALITY("Nationality"),
        PLACE_OF_BIRTH("Place Of Birth"),
        PHOTO("Photo");


        private final String name;

        private DefaultAttribute(String name) {
                this.name = name;
        }

        public String getName() {
                return this.name;
        }
}
