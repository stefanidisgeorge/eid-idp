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

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface towards the configuration of the eID IdP.
 *
 * @author Frank Cornelis
 */
public interface IdentityProviderConfiguration {

    /**
     * Gives back the secret used to HMAC the user identifiers.
     *
     * @return secret, or <code>null</code> if not set.
     */
    byte[] getHmacSecret();

    /**
     * @return the identity of this eID IdP system.
     */
    KeyStore.PrivateKeyEntry getIdentity();

    /**
     * @return certificate chain of the eID IdP identity.
     */
    List<X509Certificate> getIdentityCertificateChain();}
