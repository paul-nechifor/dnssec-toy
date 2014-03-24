package net.nechifor.dnssec_toy.logic;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.xml.bind.DatatypeConverter;

public class MasterFileKeyPairGenerator
{
    public static void generate(File file)
    {
        if (!file.exists())
        {
            System.err.println("Master file '" + file.getPath() +
                    "' doesn't exit.");
            System.exit(1);
        }

        File keyFile = new File(file.getParentFile(),
                "keypairs_" + file.getName());
        try
        {
            FileWriter writer = new FileWriter(keyFile);
            PrintWriter printer = new PrintWriter(writer);

            // Key Signing Key.
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.genKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            String privateKey64 = DatatypeConverter.printBase64Binary(
                    privateKey.getEncoded());
            String publicKey64 = DatatypeConverter.printBase64Binary(
                    publicKey.getEncoded());

            printer.print(privateKey64 + "\n" + publicKey64 + "\n");

            // Zone Signing Key.
            keyPair = keyGen.genKeyPair();
            privateKey = (RSAPrivateKey) keyPair.getPrivate();
            publicKey = (RSAPublicKey) keyPair.getPublic();
            privateKey64 = DatatypeConverter.printBase64Binary(
                    privateKey.getEncoded());
            publicKey64 = DatatypeConverter.printBase64Binary(
                    publicKey.getEncoded());

            printer.print(privateKey64 + "\n" + publicKey64 + "\n");

            printer.close();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            System.exit(1);
        }
    }
}