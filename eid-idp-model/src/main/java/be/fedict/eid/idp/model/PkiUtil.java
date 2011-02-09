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

import be.fedict.eid.idp.model.exception.KeyLoadException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.PEMReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public abstract class PkiUtil {

        private static final Log LOG = LogFactory.getLog(PkiUtil.class);

        public static X509Certificate getCertificate(byte[] certificateBytes)
                throws CertificateException {

                CertificateFactory certificateFactory = CertificateFactory
                        .getInstance("X.509");
                return (X509Certificate) certificateFactory
                        .generateCertificate(new ByteArrayInputStream(certificateBytes));
        }

        public static PrivateKey getPrivateFromPem(byte[] keyBytes)
                throws KeyLoadException {

                try {
                        PEMReader pemReader = new PEMReader(
                                new InputStreamReader(
                                        new ByteArrayInputStream(keyBytes)));

                        Object object = pemReader.readObject();
                        pemReader.close();

                        if (null == object) {
                                return null;
                        }

                        if (!(object instanceof KeyPair)) {
                                throw new KeyLoadException("Invalid key format");
                        }

                        return ((KeyPair) object).getPrivate();
                } catch (IOException e) {
                        throw new KeyLoadException(e);
                }
        }

        public static PrivateKey getPrivate(byte[] keyBytes) throws KeyLoadException {

                // try DSA
                try {
                        KeyFactory dsaKeyFactory = KeyFactory.getInstance("DSA");
                        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                                keyBytes);
                        try {
                                return dsaKeyFactory.generatePrivate(privateKeySpec);
                        } catch (InvalidKeySpecException e) {
                                // try RSA
                                KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
                                try {
                                        return rsaKeyFactory.generatePrivate(privateKeySpec);
                                } catch (InvalidKeySpecException e1) {
                                        throw new KeyLoadException(e);
                                }

                        }
                } catch (NoSuchAlgorithmException e) {
                        throw new KeyLoadException(e);
                }
        }
}
