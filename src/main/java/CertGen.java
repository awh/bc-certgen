
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;


public class CertGen {
    
    public static X509Certificate generateCACertificate(Date notBefore, Date notAfter, String distinguishedName, KeyPair authorityKey, KeyPair subjectKey) throws Exception {
        final BigInteger serialNumber = BigInteger.valueOf(1);
        final X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(serialNumber);
        certGen.setNotBefore(notBefore);
        certGen.setNotAfter(notAfter);
        certGen.setIssuerDN(new X509Principal(distinguishedName));
        certGen.setSubjectDN(new X509Principal(distinguishedName));
        certGen.setPublicKey(subjectKey.getPublic());
        certGen.setSignatureAlgorithm("SHA512withRSA");

        certGen.addExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign));
        certGen.addExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(true));
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(authorityKey.getPublic()));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(subjectKey.getPublic()));
                
        return certGen.generate(authorityKey.getPrivate(), "BC");
    }
    
    public static X509Certificate generateSSLCertificate(Date notBefore, Date notAfter, String issuerDN, String dnsName, KeyPair authorityKey, KeyPair subjectKey) throws Exception {
        final BigInteger serialNumber = BigInteger.valueOf(2);
        final X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(new X509Principal(issuerDN));
        certGen.setNotBefore(notBefore);
        certGen.setNotAfter(notAfter);
        certGen.setPublicKey(subjectKey.getPublic());
        certGen.setSignatureAlgorithm("SHA512withRSA");

        certGen.addExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        certGen.addExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(false));
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(authorityKey.getPublic()));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(subjectKey.getPublic()));
        
        final GeneralName[] subjectAltNames = new GeneralName[] {
                new GeneralName(GeneralName.dNSName, dnsName)
            };
            
        certGen.addExtension(X509Extensions.SubjectAlternativeName, true,
                new DERSequence(subjectAltNames));
        
        return certGen.generate(authorityKey.getPrivate(), "BC");
    }
    
    public static X509Certificate generateClientCertificate(Date notBefore, Date notAfter, String issuerDN, String rfc822Name, KeyPair authorityKey, KeyPair subjectKey) throws Exception {
        final BigInteger serialNumber = BigInteger.valueOf(3);
        final X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(new X509Principal(issuerDN));
        certGen.setSubjectDN(new X509Principal("CN=Some Body, O=example.com"));
        certGen.setNotBefore(notBefore);
        certGen.setNotAfter(notAfter);
        certGen.setPublicKey(subjectKey.getPublic());
        certGen.setSignatureAlgorithm("SHA512withRSA");

        certGen.addExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.digitalSignature));
        certGen.addExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(false));
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(authorityKey.getPublic()));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(subjectKey.getPublic()));
        
        final GeneralName[] subjectAltNames = new GeneralName[] {
                new GeneralName(GeneralName.rfc822Name, rfc822Name)
            };
            
        certGen.addExtension(X509Extensions.SubjectAlternativeName, false,
                new DERSequence(subjectAltNames));
        
        return certGen.generate(authorityKey.getPrivate(), "BC");
    }
    
    public static void writePrivateKeyAndCertificate(PrivateKey privateKey, X509Certificate certificate, String filePrefix) throws Exception {
        final FileOutputStream certOutputStream = new FileOutputStream(filePrefix + ".cert");
        certOutputStream.write(certificate.getEncoded());
        certOutputStream.close();

        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final RSAPrivateCrtKeySpec keySpec = keyFactory.getKeySpec(privateKey, RSAPrivateCrtKeySpec.class);
        
        final RSAPrivateKeyStructure s = new RSAPrivateKeyStructure(
                keySpec.getModulus(),
                keySpec.getPublicExponent(),
                keySpec.getPrivateExponent(),
                keySpec.getPrimeP(),
                keySpec.getPrimeQ(),
                keySpec.getPrimeExponentP(),
                keySpec.getPrimeExponentQ(),
                keySpec.getCrtCoefficient());
        
        final FileOutputStream keyOutputStream = new FileOutputStream(filePrefix + ".key");
        keyOutputStream.write(s.toASN1Object().getEncoded());
        keyOutputStream.close();
    }
    
    public static Date getNotBefore() {
        final Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        calendar.set(Calendar.MILLISECOND, 0);
        return calendar.getTime();
    }
    
    public static Date getNotAfter() {
        final Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        calendar.set(Calendar.MILLISECOND, 0);        
        calendar.set(Calendar.YEAR, 2019);
        return calendar.getTime();
    }

    public static void writeKeyStore(String type, String file, PrivateKey privateKey, Certificate... chain) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance(type);
        
        keyStore.load(null, null);
        keyStore.setKeyEntry("alias", privateKey, "password".toCharArray(), chain);        
        keyStore.store(new FileOutputStream(file), "password".toCharArray());
    }
    
    public static void main( String[] args ) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        final SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        final Date notBefore = getNotBefore();
        final Date notAfter = getNotAfter();
        
        keyPairGenerator.initialize(1024, secureRandom);
        
        final KeyPair caKeyPair = keyPairGenerator.generateKeyPair();
        final KeyPair sslKeyPair = keyPairGenerator.generateKeyPair();
        final KeyPair clientKeyPair = keyPairGenerator.generateKeyPair();
        
        final X509Certificate caCert = generateCACertificate(notBefore, notAfter, "cn=example, o=example.com", caKeyPair, caKeyPair);
        final X509Certificate sslCert = generateSSLCertificate(notBefore, notAfter, "cn=example, o=example.com", "localhost", caKeyPair, sslKeyPair);
        final X509Certificate clientCert = generateClientCertificate(notBefore, notAfter, "cn=example, o=example.com", "nobody@example.com", caKeyPair, clientKeyPair);
                
        writePrivateKeyAndCertificate(caKeyPair.getPrivate(), caCert, "ca");
        writePrivateKeyAndCertificate(sslKeyPair.getPrivate(), sslCert, "ssl");
        writePrivateKeyAndCertificate(clientKeyPair.getPrivate(), clientCert, "client");
        
        writeKeyStore("jks", "ssl.keystore", sslKeyPair.getPrivate(), sslCert, caCert);
        writeKeyStore("PKCS12", "client.p12", clientKeyPair.getPrivate(), clientCert, caCert);
    }
    
}
