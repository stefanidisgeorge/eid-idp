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
import java.util.Set;

@Entity
@Table(name = Constants.DATABASE_TABLE_PREFIX + "attributes")
@NamedQueries(@NamedQuery(name = AttributeEntity.LIST_ALL,
        query = "FROM AttributeEntity"))
public class AttributeEntity implements Serializable {

        private static final long serialVersionUID = 1L;

        public static final String LIST_ALL = "idp.attr.all";

        private String uri;
        private Set<AttributeProtocolUriEntity> protocolUris;

        public AttributeEntity() {
                super();
        }

        public AttributeEntity(String uri) {
                this.uri = uri;
        }

        @Id
        public String getUri() {
                return this.uri;
        }

        public void setUri(String uri) {
                this.uri = uri;
        }

        @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.REMOVE,
                mappedBy = AttributeProtocolUriEntity.ATTRIBUTE_COLUMN_NAME)
        public Set<AttributeProtocolUriEntity> getProtocolUris() {
                return this.protocolUris;
        }

        public void setProtocolUris(Set<AttributeProtocolUriEntity> protocolUris) {
                this.protocolUris = protocolUris;
        }

        @SuppressWarnings("unchecked")
        public static List<AttributeEntity> listAttributes(EntityManager entityManager) {

                Query query = entityManager.createNamedQuery(LIST_ALL);
                return query.getResultList();
        }
}
