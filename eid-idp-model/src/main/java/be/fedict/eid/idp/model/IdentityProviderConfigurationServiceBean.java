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

import javax.ejb.EJB;
import javax.ejb.Stateless;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

@Stateless
public class IdentityProviderConfigurationServiceBean implements
		IdentityProviderConfigurationService {

	@EJB
	private ConfigManager configManager;

	@Override
	public byte[] getHmacSecret() {
		String secretValue = this.configManager.getHmacSecret();
		if (null == secretValue) {
			return null;
		}
		try {
			return Hex.decodeHex(secretValue.toCharArray());
		} catch (DecoderException e) {
			throw new RuntimeException("HEX decoder error: " + e.getMessage(),
					e);
		}
	}
}
