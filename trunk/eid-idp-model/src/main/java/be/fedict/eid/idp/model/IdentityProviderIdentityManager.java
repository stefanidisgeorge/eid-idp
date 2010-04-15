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

package be.fedict.eid.idp.model;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.ejb.Local;

@Local
public interface IdentityProviderIdentityManager {

	/**
	 * When the system starts up we need to manage the eID IdP identity somehow.
	 * This is the place.
	 */
	void startup();

	/**
	 * Gives back the eID IdP identity.
	 * 
	 * @return the X509 certificate representing the identity of the eID IdP
	 *         system.
	 */
	X509Certificate getIdentity();

	/**
	 * Gives back the private key corresponding with the eID IdP identity.
	 * 
	 * @return
	 */
	PrivateKey getPrivateIdentityKey();
}
