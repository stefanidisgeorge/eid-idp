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

package be.fedict.eid.idp.admin.webapp.bean;

import be.fedict.eid.idp.admin.webapp.AdminConstants;
import be.fedict.eid.idp.admin.webapp.RP;
import be.fedict.eid.idp.entity.AttributeEntity;
import be.fedict.eid.idp.entity.RPAttributeEntity;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.model.AttributeService;
import be.fedict.eid.idp.model.RPService;
import org.apache.commons.io.FileUtils;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.*;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.annotations.datamodel.DataModelSelection;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.log.Log;
import org.richfaces.event.UploadEvent;
import org.richfaces.model.UploadItem;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

@Stateful
@Name("idpRP")
@LocalBinding(jndiBinding = AdminConstants.ADMIN_JNDI_CONTEXT + "RPBean")
public class RPBean implements RP {

        private static final String RP_LIST_NAME = "idpRPList";
        private static final String SELECTED_RP = "selectedRP";
        private static final String UPLOADED_CERTIFICATE = "uploadedCertificate";

        @Logger
        private Log log;

        @EJB
        private RPService rpService;

        @EJB
        private AttributeService attributeService;

        @In
        FacesMessages facesMessages;


        @SuppressWarnings("unused")
        @DataModel(RP_LIST_NAME)
        private List<RPEntity> rpList;

        @DataModelSelection(RP_LIST_NAME)
        @In(value = SELECTED_RP, required = false)
        @Out(value = SELECTED_RP, required = false, scope = ScopeType.CONVERSATION)
        private RPEntity selectedRP;

        @In(value = UPLOADED_CERTIFICATE, required = false)
        @Out(value = UPLOADED_CERTIFICATE, required = false, scope = ScopeType.CONVERSATION)
        private byte[] certificateBytes;

        private List<String> sourceAttributes;
        private List<String> selectedAttributes;

        @Override
        @PostConstruct
        public void postConstruct() {

                this.sourceAttributes = null;
                this.selectedAttributes = null;
        }

        @Override
        @Remove
        @Destroy
        public void destroy() {
        }

        @Override
        @Factory(RP_LIST_NAME)
        public void rpListFactory() {

                this.rpList = this.rpService.listRPs();
        }

        @Override
        @Begin(join = true)
        public String add() {

                this.log.debug("add RP");
                this.selectedRP = new RPEntity();
                for (AttributeEntity attribute : this.attributeService.listAttributes()) {
                        this.selectedRP.getAttributes().add(
                                new RPAttributeEntity(this.selectedRP, attribute));
                }
                return "modify";
        }

        @Override
        @Begin(join = true)
        public String modify() {

                this.log.debug("modify RP: #0", this.selectedRP.getName());
                return "modify";
        }

        @Override
        @End
        public String save() {

                this.log.debug("save RP: #0", this.selectedRP.getName());
                this.rpService.save(this.selectedRP);
                rpListFactory();
                return "success";
        }

        @Override
        @Begin(join = true)
        public void select() {

                this.log.debug("selected RP: #0", this.selectedRP.getName());
        }

        /**
         * {@inheritDoc}
         */
        @Override
        @End
        public String remove() {

                this.log.debug("remove RP: #0", this.selectedRP.getName());
                this.rpService.remove(this.selectedRP);
                rpListFactory();
                return "success";
        }

        @Override
        @End
        public String back() {
                return "back";
        }

        @Override
        public String selectAttributes() {
                return "select";
        }

        @Override
        public String saveSelect() {

                this.log.debug("save selected attributes");
                this.selectedRP =
                        this.attributeService.setAttributes(this.selectedRP,
                                this.selectedAttributes);
                return "success";
        }

        @Override
        public void initSelect() {

                this.log.debug("init select");
                if (null != this.selectedRP) {
                        this.selectedAttributes = new LinkedList<String>();
                        for (RPAttributeEntity rpAttribute : this.selectedRP.getAttributes()) {
                                this.selectedAttributes.add(rpAttribute.getAttribute().getUri());
                        }
                }
        }

        @Override
        @Begin(join = true)
        public void uploadListener(UploadEvent event) throws IOException {
                UploadItem item = event.getUploadItem();
                this.log.debug(item.getContentType());
                this.log.debug(item.getFileSize());
                this.log.debug(item.getFileName());
                if (null == item.getData()) {
                        // meaning createTempFiles is set to true in the SeamFilter
                        this.certificateBytes = FileUtils.readFileToByteArray(item
                                .getFile());
                } else {
                        this.certificateBytes = item.getData();
                }

                try {
                        this.selectedRP.setCertificate(getCertificate(this.certificateBytes));
                } catch (CertificateException e) {
                        this.facesMessages.addToControl("upload", "Invalid certificate");
                }
        }

        private X509Certificate getCertificate(byte[] certificateBytes)
                throws CertificateException {

                CertificateFactory certificateFactory = CertificateFactory
                        .getInstance("X.509");
                return (X509Certificate) certificateFactory
                        .generateCertificate(new ByteArrayInputStream(certificateBytes));
        }

        @Override
        public List<String> getSourceAttributes() {

                List<AttributeEntity> attributes = this.attributeService.
                        listAttributes();
                this.sourceAttributes = new LinkedList<String>();
                for (AttributeEntity attribute : attributes) {
                        if (null != this.selectedAttributes
                                && !this.selectedAttributes.contains(attribute.getUri())) {
                                this.sourceAttributes.add(attribute.getUri());
                        }
                }
                return this.sourceAttributes;
        }

        @Override
        public void setSourceAttributes(List<String> sourceAttributes) {

                this.sourceAttributes = sourceAttributes;
        }

        @Override
        public List<String> getSelectedAttributes() {

                return this.selectedAttributes;
        }

        @Override
        public void setSelectedAttributes(List<String> selectedAttributes) {

                this.selectedAttributes = selectedAttributes;
        }

}
