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

package be.fedict.eid.idp.model.bean;

import be.fedict.eid.idp.entity.ConfigPropertyEntity;
import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

@Stateless
public class ConfigurationBean implements Configuration {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * {@inheritDoc}
     */
    public void setValue(ConfigProperty configProperty, Object value) {

        setValue(configProperty, null, value);
    }


    /**
     * {@inheritDoc}
     */
    public void setValue(ConfigProperty configProperty, String index, Object value) {

        String propertyValue;
        if (null != value) {
            Class<?> expectedType = configProperty.getType();
            Class<?> type = value.getClass();
            if (!expectedType.isAssignableFrom(type)) {
                throw new IllegalArgumentException("value has incorrect type: "
                        + type.getClass().getName());
            }
            Object castedValue = expectedType.cast(value);
            if (expectedType.isEnum()) {
                Enum<?> enumValue = (Enum<?>) castedValue;
                propertyValue = enumValue.name();
            } else {
                propertyValue = castedValue.toString();
            }
        } else {
            propertyValue = null;
        }

        String propertyName = getPropertyName(configProperty, index);
        ConfigPropertyEntity configPropertyEntity = this.entityManager.find(
                ConfigPropertyEntity.class, propertyName);
        if (null == configPropertyEntity) {
            configPropertyEntity = new ConfigPropertyEntity(
                    propertyName, propertyValue);
            this.entityManager.persist(configPropertyEntity);
        } else {
            configPropertyEntity.setValue(propertyValue);
        }
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings({"unchecked", "static-access"})
    public <T> T getValue(ConfigProperty configProperty, Class<T> type) {
        return getValue(configProperty, null, type);
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings({"unchecked", "static-access"})
    public <T> T getValue(ConfigProperty configProperty, String index, Class<T> type) {

        if (!type.equals(configProperty.getType())) {
            throw new IllegalArgumentException("incorrect type: "
                    + type.getName());
        }

        String propertyName = getPropertyName(configProperty, index);

        ConfigPropertyEntity configPropertyEntity = this.entityManager.find(
                ConfigPropertyEntity.class, propertyName);
        if (null == configPropertyEntity) {
            return null;
        }
        String strValue = configPropertyEntity.getValue();
        if (null == strValue) {
            return null;
        }
        if (String.class == configProperty.getType()) {
            return (T) strValue;
        }
        if (Boolean.class == configProperty.getType()) {
            Boolean value = Boolean.parseBoolean(strValue);
            return (T) value;
        }
        if (Integer.class == configProperty.getType()) {
            Integer value = Integer.parseInt(strValue);
            return (T) value;
        }
        if (configProperty.getType().isEnum()) {
            Enum<?> e = (Enum<?>) configProperty.getType().getEnumConstants()[0];
            return (T) Enum.valueOf(e.getClass(), strValue);
        }
        throw new RuntimeException("unsupported type: "
                + configProperty.getType().getName());
    }

    private String getPropertyName(ConfigProperty configProperty, String index) {

        String propertyName = configProperty.getName();
        if (null != index) {
            propertyName += '-' + index;
        }
        return propertyName;
    }
}
