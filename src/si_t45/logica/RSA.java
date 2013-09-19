package si_t45.logica;

import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.xml.bind.DatatypeConverter;

public class RSA
{
    public static RSAPublicKey publicKeyFromBytes(byte[] bytes)
    {
        try
        {
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    public static RSAPrivateKey privateKeyFromBytes(byte[] bytes)
    {
        try
        {
            PKCS8EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(pubKeySpec);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    public static String sign(byte[] bytes, RSAPrivateKey privateKey)
    {
        try
        {
            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initSign(privateKey);
            sig.update(bytes);
            byte[] sigBytes = sig.sign();
            return DatatypeConverter.printBase64Binary(sigBytes);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    public static boolean verify(byte[] bytes, String signature,
            RSAPublicKey publicKey)
    {
        try
        {
            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initVerify(publicKey);
            sig.update(bytes);
            byte[] sigBytes = DatatypeConverter.parseBase64Binary(
                    signature);
            return sig.verify(sigBytes);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.exit(1);
        }
        return false;
    }
}
