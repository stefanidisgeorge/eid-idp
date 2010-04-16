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

package be.fedict.eid.idp.protocol.ws_federation;

/**
 * WS-Federation related constants. See also: OASIS Identity Metasystem
 * Interoperability Version 1.0
 * 
 * @author Frank Cornelis
 */
public class WSFederationConstants {

	public static final String FIRST_NAME_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";

	public static final String LAST_NAME_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";

	public static final String STREET_ADDRESS_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress";

	public static final String LOCALITY_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality";

	public static final String POSTAL_CODE_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode";

	public static final String COUNTRY_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country";

	public static final String DATE_OF_BIRTH_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth";

	public static final String GENDER_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender";

	public static final String PPID_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier";

	public WSFederationConstants() {
		super();
	}
}
