package si_t45.logica;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

public class SHA1
{
    public static String digest(byte[] bytes)
    {
        try
        {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] ret = md.digest(bytes);
            return DatatypeConverter.printHexBinary(ret);
        }
        catch (NoSuchAlgorithmException ex)
        {
            ex.printStackTrace();
            System.exit(1);
        }

        return null;
    }
}
