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

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import be.fedict.eid.idp.entity.ConfigEntity;

@Stateless
public class ConfigManagerBean implements ConfigManager {

	@PersistenceContext
	private EntityManager entityManager;

	public String getXkmsUrl() {
		return getConfigValue(ConfigNames.XKMS_URL);
	}

	public void setXkmsUrl(String xkmsUrl) {
		setConfigValue(ConfigNames.XKMS_URL, xkmsUrl);
	}

	private String getConfigValue(ConfigNames configName) {
		ConfigEntity config = this.entityManager.find(ConfigEntity.class,
				configName.name());
		if (null != config) {
			String value = config.getValue();
			if (null == value) {
				return null;
			}
			if (value.isEmpty()) {
				return null;
			}
			return value;
		}
		return null;
	}

	private void setConfigValue(ConfigNames configName, String value) {
		ConfigEntity config = this.entityManager.find(ConfigEntity.class,
				configName.name());
		if (null == config) {
			config = new ConfigEntity(configName.name(), value);
			this.entityManager.persist(config);
		} else {
			config.setValue(value);
		}
	}

	@Override
	public String getHmacSecret() {
		return getConfigValue(ConfigNames.HMAC_SECRET);
	}

	@Override
	public void setHmacSecret(String hmacSecret) {
		setConfigValue(ConfigNames.HMAC_SECRET, hmacSecret);
	}
}
