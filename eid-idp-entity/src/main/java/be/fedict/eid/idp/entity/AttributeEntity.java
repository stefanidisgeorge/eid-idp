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

package be.fedict.eid.idp.entity;

import javax.persistence.*;
import java.io.Serializable;
import java.util.List;

@Entity
@Table(name = Constants.DATABASE_TABLE_PREFIX + "attributes")
@NamedQueries(@NamedQuery(name = AttributeEntity.LIST_ALL,
        query = "FROM AttributeEntity"))
public class AttributeEntity implements Serializable {

        private static final long serialVersionUID = 1L;

        public static final String LIST_ALL = "idp.attr.all";

        private String name;

        public AttributeEntity() {
                super();
        }

        public AttributeEntity(String name) {
                this.name = name;
        }

        @Id
        public String getName() {
                return this.name;
        }

        public void setName(String name) {
                this.name = name;
        }

        @SuppressWarnings("unchecked")
        public static List<AttributeEntity> listAttributes(EntityManager entityManager) {

                Query query = entityManager.createNamedQuery(LIST_ALL);
                return query.getResultList();
        }
}
