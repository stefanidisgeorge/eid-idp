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

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

import javax.persistence.*;
import java.io.Serializable;
import java.util.List;

@Entity
@Table(name = Constants.DATABASE_TABLE_PREFIX + "attribute_uri")
@NamedQueries({@NamedQuery(name = AttributeProtocolUriEntity.LIST_ALL,
        query = "SELECT apu FROM AttributeProtocolUriEntity AS apu " +
                "ORDER BY apu.attribute")})
public class AttributeProtocolUriEntity implements Serializable {

        private static final long serialVersionUID = 1L;

        public static final String LIST_ALL = "idp.attr.uri.all";

        public static final String ATTRIBUTE_COLUMN_NAME = "attribute";

        private AttributeProtocolUriPK pk;

        private AttributeEntity attribute;
        private String uri;

        public AttributeProtocolUriEntity() {
                super();
        }

        public AttributeProtocolUriEntity(String protocolId,
                                          AttributeEntity attribute,
                                          String uri) {
                this.pk = new AttributeProtocolUriPK(protocolId, attribute);
                this.attribute = attribute;
                this.uri = uri;
        }

        @EmbeddedId
        @AttributeOverrides({
                @AttributeOverride(name = AttributeProtocolUriPK.ATTRIBUTE_COLUMN_NAME,
                        column = @Column(name = ATTRIBUTE_COLUMN_NAME))})
        public AttributeProtocolUriPK getPk() {
                return pk;
        }

        public void setPk(AttributeProtocolUriPK pk) {
                this.pk = pk;
        }

        @ManyToOne(optional = false)
        @JoinColumn(name = ATTRIBUTE_COLUMN_NAME, insertable = false, updatable = false)
        public AttributeEntity getAttribute() {
                return attribute;
        }

        public void setAttribute(AttributeEntity attribute) {
                this.attribute = attribute;
        }

        @Column(nullable = true)
        public String getUri() {
                return this.uri;
        }

        public void setUri(String uri) {
                this.uri = uri;
        }

        @SuppressWarnings("unchecked")
        public static List<AttributeProtocolUriEntity> listAll(EntityManager entityManager) {

                Query query = entityManager.createNamedQuery(LIST_ALL);
                return query.getResultList();

        }

        @Override
        public boolean equals(Object obj) {

                if (this == obj) {
                        return true;
                }
                if (null == obj) {
                        return false;
                }
                if (!(obj instanceof AttributeProtocolUriEntity)) {
                        return false;
                }
                AttributeProtocolUriEntity rhs = (AttributeProtocolUriEntity) obj;
                return new EqualsBuilder().append(this.pk, rhs.pk).isEquals();
        }

        @Override
        public int hashCode() {

                return new HashCodeBuilder().append(this.pk).toHashCode();
        }

        @Override
        public String toString() {

                return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                        .append("pk", this.pk).toString();
        }
}
