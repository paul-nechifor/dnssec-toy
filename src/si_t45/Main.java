package si_t45;

import java.io.File;
import si_t45.net.AuthoritativeServer;
import si_t45.logica.CreateAndSign;
import si_t45.logica.MasterFileKeyPairGenerator;
import si_t45.net.Resolver;

public class Main
{
    public static void main(String[] args)
    {
        if (args.length == 0)
            showSelectMessage();

        if (args[0].equals("--autho"))
            startAuthoritativeServer(args);
        else if(args[0].equals("--res"))
            startResolver();
        else if(args[0].equals("--genkeypairs"))
            generateKeyPairs(args);
        else if(args[0].equals("--sign"))
            signZones(args);
        else
            showSelectMessage();
    }

    public static void showSelectMessage()
    {
        System.err.println("Use `--autho` to start an authoritative server.");
        System.err.println("Use `--res` to start a resolver.");
        System.err.println("Use `--genkeypairs` to generate the key pairs.");
        System.err.println("Use `--sign` to sign zones.");
        System.exit(1);
    }

    public static void startAuthoritativeServer(String[] args)
    {
        if (args.length < 4)
        {
            System.err.println("Use `--autho <name> <port> <masterFile>` to " +
		    "start the authoritative server.");
            System.exit(1);
        }

        String name = args[1];
        int port = Integer.parseInt(args[2]);
        File masterFile = new File(args[3]);
        AuthoritativeServer server = new AuthoritativeServer(name, port,
                masterFile);
        
        try
        {
            server.start();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            System.exit(1);
        }
    }

    public static void startResolver()
    {
        Resolver resolver = new Resolver();
        resolver.start();
    }

    public static void generateKeyPairs(String[] args)
    {
        if (args.length < 2)
        {
            System.err.println("Use `--genkeypairs <masterFile1> " +
                    "<masterFile2> ...` to generate the KSK pair and ZSK pair" +
                    "for every master file.");
            System.exit(1);
        }

        for (int i = 1; i < args.length; i++)
            MasterFileKeyPairGenerator.generate(new File(args[i]));
    }

    public static void signZones(String[] args)
    {
        if (args.length < 2)
        {
            System.err.println("Use `--sign <masterFile1>  <masterFile2> " +
                    "...` to generate the appropriate DNSSEC RR from the " +
                    "specified master files and to sign them with associated " +
                    "keys. If the key files don't exist, use `--genkeypairs` " +
                    "to generate them.");
            System.exit(1);
        }

        for (int i = 1; i < args.length; i++)
        {
            CreateAndSign cas = new CreateAndSign(new File(args[i]));
            cas.start();
        }
    }
}