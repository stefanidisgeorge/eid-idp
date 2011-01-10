/*
 * eID Identity Provider Project.
 * Copyright (C) 2011 FedICT.
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

package be.fedict.eid.idp.sp.protocol.saml2.spi;

import java.util.Map;

/**
 * SPI for authentication request services. Using an authentication request
 * service allows for run-time configuration of the
 * AuthenticationRequestServlet.
 * 
 * @author Frank Cornelis.
 * 
 */
public interface AuthenticationRequestService {

	/**
	 * Gives back the destination URL of the eID IdP SAML2 protocol entry point.
	 * 
	 * @return
	 */
	String getIdPDestination();

	/**
	 * Gives back the relay state to be used towards the eID IdP SAML2 protocol
	 * entry point.
	 * 
	 * @param parameterMap
	 *            the HTTP parameter map.
	 * 
	 * @return
	 */
	String getRelayState(Map<String, String[]> parameterMap);
}
