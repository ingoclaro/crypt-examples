import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.security.cert.*;
import net.oauth.signature.pem.*;

class Encrypt {

  public static void main(String[] args) throws IOException, Exception {

    if (args.length < 2) {
      System.err.println("Usage: java Encrypt "+
      " Public_Key_Filename Input_String_data");
      System.exit(1);
    }

    String publicKeyFilename = args[0].trim();
    String text = args[1].trim();

    PublicKey key = getPublicKey(publicKeyFilename);

    RSAEncryptUtil rsaEncryptUtil = new RSAEncryptUtil();
    String encrypted = rsaEncryptUtil.encrypt(text, key);
    System.out.printf("%s",encrypted);
  }

  private static PublicKey getPublicKey(String publicKeyFilename)
    throws GeneralSecurityException, IOException {
      PEMReader reader = new PEMReader(publicKeyFilename);
      byte[] bytes = reader.getDerBytes();
      PublicKey pubKey;

      if (PEMReader.PUBLIC_X509_MARKER.equals(reader.getBeginMarker())) {
          KeySpec keySpec = new X509EncodedKeySpec(bytes);
          KeyFactory fac = KeyFactory.getInstance("RSA");
          pubKey = fac.generatePublic(keySpec);
      } else if (PEMReader.CERTIFICATE_X509_MARKER.equals(reader.getBeginMarker())) {
          pubKey = getPublicKeyFromDerCert(bytes);
      } else {
          throw new IOException("Invalid PEM fileL: Unknown marker for " +
                  " public key or cert " + reader.getBeginMarker());
      }

      return pubKey;
  }

  private static PublicKey getPublicKeyFromDerCert(byte[] certObject)
          throws GeneralSecurityException {
      CertificateFactory fac = CertificateFactory.getInstance("X509");
      ByteArrayInputStream in = new ByteArrayInputStream(certObject);
      X509Certificate cert = (X509Certificate)fac.generateCertificate(in);
      return cert.getPublicKey();
  }

}
