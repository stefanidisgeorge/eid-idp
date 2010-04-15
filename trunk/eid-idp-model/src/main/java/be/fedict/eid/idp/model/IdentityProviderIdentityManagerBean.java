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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Enumeration;
import java.util.List;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;

import be.fedict.eid.idp.model.entity.IdentityProviderIdentityEntity;

@Stateless
public class IdentityProviderIdentityManagerBean implements
		IdentityProviderIdentityManager {

	private static final Log LOG = LogFactory
			.getLog(IdentityProviderIdentityManagerBean.class);

	@PersistenceContext
	private EntityManager entityManager;

	private KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey)
			throws IOException {
		ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
				.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());
		return new SubjectKeyIdentifier(info);
	}

	private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey)
			throws IOException {

		ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
				.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());

		return new AuthorityKeyIdentifier(info);
	}

	private X509Certificate generateSelfSignedCertificate(KeyPair keyPair,
			String subjectDn, DateTime notBefore, DateTime notAfter)
			throws Exception {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		String signatureAlgorithm = "SHA1WithRSAEncryption";
		X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
		certificateGenerator.reset();
		certificateGenerator.setPublicKey(subjectPublicKey);
		certificateGenerator.setSignatureAlgorithm(signatureAlgorithm);
		certificateGenerator.setNotBefore(notBefore.toDate());
		certificateGenerator.setNotAfter(notAfter.toDate());
		X509Principal issuerDN = new X509Principal(subjectDn);
		certificateGenerator.setIssuerDN(issuerDN);
		certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
		certificateGenerator.setSerialNumber(new BigInteger(128,
				new SecureRandom()));

		certificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier,
				false, createSubjectKeyId(subjectPublicKey));
		PublicKey issuerPublicKey;
		issuerPublicKey = subjectPublicKey;
		certificateGenerator.addExtension(
				X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(issuerPublicKey));

		certificateGenerator.addExtension(X509Extensions.BasicConstraints,
				false, new BasicConstraints(true));

		X509Certificate certificate;
		certificate = certificateGenerator.generate(issuerPrivateKey);

		/*
		 * Next certificate factory trick is needed to make sure that the
		 * certificate delivered to the caller is provided by the default
		 * security provider instead of BouncyCastle. If we don't do this trick
		 * we might run into trouble when trying to use the CertPath validator.
		 */
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificate
						.getEncoded()));
		return certificate;
	}

	private void persistKey(File pkcs12keyStore, PrivateKey privateKey,
			X509Certificate certificate, char[] keyStorePassword,
			char[] keyEntryPassword) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("pkcs12");
		keyStore.load(null, keyStorePassword);
		keyStore.setKeyEntry("default", privateKey, keyEntryPassword,
				new Certificate[] { certificate });
		FileOutputStream keyStoreOut = new FileOutputStream(pkcs12keyStore);
		keyStore.store(keyStoreOut, keyStorePassword);
		keyStoreOut.close();
	}

	@Override
	public void startup() {
		LOG.debug("startup");
		List<IdentityProviderIdentityEntity> idpIdentities = IdentityProviderIdentityEntity
				.getAll(this.entityManager);
		if (false == idpIdentities.isEmpty()) {
			return;
		}

		LOG
				.debug("no IdP identities available, will create a temporary identity right now...");
		KeyPair keyPair;
		try {
			keyPair = generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException("could not generate RSA key pair: "
					+ e.getMessage(), e);
		}
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate;
		try {
			certificate = generateSelfSignedCertificate(keyPair, "CN=Test",
					notBefore, notAfter);
		} catch (Exception e) {
			throw new RuntimeException(
					"could not generate self-signed certificate: "
							+ e.getMessage(), e);
		}
		File tmpP12File;
		try {
			tmpP12File = File.createTempFile("eid-idp-", ".p12");
		} catch (IOException e) {
			throw new RuntimeException("error creating temp keystore file: "
					+ e.getMessage(), e);
		}
		try {
			persistKey(tmpP12File, keyPair.getPrivate(), certificate, "secret"
					.toCharArray(), "secret".toCharArray());
		} catch (Exception e) {
			throw new RuntimeException("error persisting the P12 keystore: "
					+ e.getMessage(), e);
		}

		IdentityProviderIdentityEntity identityEntity = new IdentityProviderIdentityEntity(
				tmpP12File.getAbsolutePath(), "secret");
		this.entityManager.persist(identityEntity);
		LOG.debug("eID IdP identity: " + identityEntity.getId());
	}

	@Override
	public X509Certificate getIdentity() {
		PrivateKeyEntry privateKeyEntry = getPrivateKeyEntry();
		X509Certificate certificate = (X509Certificate) privateKeyEntry
				.getCertificate();
		return certificate;
	}

	private PrivateKeyEntry getPrivateKeyEntry() {
		List<IdentityProviderIdentityEntity> idpIdentities = IdentityProviderIdentityEntity
				.getAll(this.entityManager);
		if (idpIdentities.isEmpty()) {
			throw new IllegalStateException("no eID IdP identity present");
		}
		IdentityProviderIdentityEntity identityEntity = idpIdentities.get(0);
		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("PKCS12");
		} catch (KeyStoreException e) {
			throw new RuntimeException("p12 error");
		}
		String p12Location = identityEntity.getP12Location();
		LOG.debug("P12 location: " + p12Location);
		FileInputStream fileInputStream;
		try {
			fileInputStream = new FileInputStream(new File(p12Location));
		} catch (FileNotFoundException e) {
			throw new RuntimeException("P12 keystore not found: " + p12Location
					+ ": " + e.getMessage(), e);
		}
		try {
			char[] password = identityEntity.getP12Password().toCharArray();
			keyStore.load(fileInputStream, password);
			Enumeration<String> aliases = keyStore.aliases();
			String alias = aliases.nextElement();
			ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(
					password);
			PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore
					.getEntry(alias, protectionParameter);
			return privateKeyEntry;
		} catch (Exception e) {
			throw new RuntimeException("error loading P12 keystore: "
					+ e.getMessage(), e);
		}
	}

	@Override
	public PrivateKey getPrivateIdentityKey() {
		PrivateKeyEntry privateKeyEntry = getPrivateKeyEntry();
		PrivateKey privateKey = privateKeyEntry.getPrivateKey();
		return privateKey;
	}
}
