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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Interface towards the configuration of the eID IdP.
 * 
 * @author Frank Cornelis
 * 
 */
public interface IdentityProviderConfiguration {

	/**
	 * Gives back the secret used to HMAC the user identifiers.
	 * 
	 * @return secret, or <code>null</code> if not set.
	 */
	byte[] getHmacSecret();

	/**
	 * Gives back the identity of this eID IdP system.
	 * 
	 * TODO: should be a chain.
	 * 
	 * @return
	 */
	X509Certificate getIdentity();

	/**
	 * Gives back the private key corresponding with the identity of this eID
	 * IdP system.
	 * 
	 * @return
	 */
	PrivateKey getPrivateIdentityKey();
}
