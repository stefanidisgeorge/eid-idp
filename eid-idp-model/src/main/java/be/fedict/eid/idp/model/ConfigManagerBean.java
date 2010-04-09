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

import be.fedict.eid.idp.model.entity.ConfigEntity;

@Stateless
public class ConfigManagerBean implements ConfigManager {

	@PersistenceContext
	private EntityManager entityManager;

	public String getXkmsUrl() {
		ConfigEntity config = this.entityManager.find(ConfigEntity.class,
				ConfigNames.XKMS_URL.name());
		if (null != config) {
			return config.getValue();
		}
		return null;
	}

	public void setXkmsUrl(String xkmsUrl) {
		ConfigEntity config = this.entityManager.find(ConfigEntity.class,
				ConfigNames.XKMS_URL.name());
		if (null == config) {
			config = new ConfigEntity(ConfigNames.XKMS_URL.name(), xkmsUrl);
			this.entityManager.persist(config);
		} else {
			config.setValue(xkmsUrl);
		}
	}
}
