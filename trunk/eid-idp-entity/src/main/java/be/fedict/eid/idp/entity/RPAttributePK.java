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

import javax.persistence.Embeddable;
import java.io.Serializable;

@Embeddable
public class RPAttributePK implements Serializable {

        private static final long serialVersionUID = 1L;

        public static final String RP_COLUMN_NAME = "rpId";
        public static final String ATTRIBUTE_COLUMN_NAME = "attributeName";

        private long rpId;
        private String attributeName;

        public RPAttributePK() {
                super();
        }

        public RPAttributePK(RPEntity rp, AttributeEntity attribute) {

                this.rpId = rp.getId();
                this.attributeName = attribute.getName();
        }

        public String getAttributeName() {
                return attributeName;
        }

        public void setAttributeName(String attributeName) {
                this.attributeName = attributeName;
        }

        public long getRpId() {
                return rpId;
        }

        public void setRpId(long rpId) {
                this.rpId = rpId;
        }

        @Override
        public boolean equals(Object obj) {

                if (null == obj) {
                        return false;
                }
                if (this == obj) {
                        return true;
                }
                if (!(obj instanceof RPAttributePK)) {
                        return false;
                }
                RPAttributePK rhs = (RPAttributePK) obj;
                return new EqualsBuilder().append(this.rpId, rhs.rpId)
                        .append(this.attributeName, rhs.attributeName).isEquals();
        }

        @Override
        public int hashCode() {

                return new HashCodeBuilder().append(this.rpId).append(
                        this.attributeName).toHashCode();
        }

        @Override
        public String toString() {

                return new ToStringBuilder(this).append("RP",
                        this.rpId).append("attribute", this.attributeName).toString();
        }
}
