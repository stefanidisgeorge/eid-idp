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

import be.fedict.eid.idp.admin.webapp.Admin;
import be.fedict.eid.idp.entity.AdministratorEntity;
import be.fedict.eid.idp.model.admin.AdminManager;
import be.fedict.eid.idp.model.exception.RemoveLastAdminException;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.*;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.annotations.datamodel.DataModelSelection;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.international.StatusMessage;
import org.jboss.seam.log.Log;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;
import java.util.List;

@Stateful
@Name("idpAdmin")
@LocalBinding(jndiBinding = "fedict/eid/idp/admin/webapp/AdminBean")
public class AdminBean implements Admin {

    private static final String ADMIN_LIST_NAME = "idpAdminList";
    private static final String SELECTED_ADMIN = "selectedAdmin";

    @Logger
    private Log log;

    @EJB
    private AdminManager adminManager;

    @In
    FacesMessages facesMessages;


    @SuppressWarnings("unused")
    @DataModel(ADMIN_LIST_NAME)
    private List<AdministratorEntity> adminList;

    @DataModelSelection(ADMIN_LIST_NAME)
    @In(value = SELECTED_ADMIN, required = false)
    @Out(value = SELECTED_ADMIN, required = false, scope = ScopeType.PAGE)
    private AdministratorEntity selectedAdmin;

    @Override
    @PostConstruct
    public void postConstruct() {
    }

    @Override
    @Remove
    @Destroy
    public void destroy() {
    }

    @Override
    @Factory(ADMIN_LIST_NAME)
    public void adminListFactory() {

        this.log.debug("admin list factory");
        this.adminList = this.adminManager.listAdmins();
    }

    @Override
    public String registerPending() {

        this.log.debug("register pending admin");
        this.adminManager.register(this.selectedAdmin);
        adminListFactory();
        return "success";
    }

    @Override
    public void select() {

        this.log.debug("selected admin: #0", this.selectedAdmin.getName());
    }

    /**
     * {@inheritDoc}
     */
    public String remove() {

        this.log.debug("remove administrator");

        try {
            this.adminManager.remove(this.selectedAdmin);
        } catch (RemoveLastAdminException e) {
            this.log.error("cannot remove last administrator");
            this.facesMessages.add(StatusMessage.Severity.ERROR,
                    "Cannot remove the last administrator");
            return null;
        }

        adminListFactory();
        return "success";
    }
}
