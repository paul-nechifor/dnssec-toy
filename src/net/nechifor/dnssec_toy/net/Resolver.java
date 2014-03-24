package net.nechifor.dnssec_toy.net;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;
import net.nechifor.dnssec_toy.data.Message;
import net.nechifor.dnssec_toy.data.MessageQuestion;
import net.nechifor.dnssec_toy.data.RDataA;
import net.nechifor.dnssec_toy.data.RDataDnsKey;
import net.nechifor.dnssec_toy.data.RDataDs;
import net.nechifor.dnssec_toy.data.RDataNs;
import net.nechifor.dnssec_toy.data.RDataNsec;
import net.nechifor.dnssec_toy.data.RDataRrSig;
import net.nechifor.dnssec_toy.data.Rr;
import net.nechifor.dnssec_toy.logic.DomainComparator;
import net.nechifor.dnssec_toy.logic.RSA;
import net.nechifor.dnssec_toy.logic.SHA1;
import net.nechifor.dnssec_toy.util.Util;

public class Resolver
{
    private IpAndPort rootServer;
    private String rootKskDigest = "820B46C4AB90C83148D14F7E1D4F65F39EC99EF0";
    private int idStart = 0;

    public Resolver()
    {
        rootServer = new IpAndPort();
        try
        {
            rootServer.name = "ns1.";
            rootServer.ipAddress = InetAddress.getByName("127.0.0.1");
            rootServer.port = 2001;
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            System.exit(1);
        }
    }

    public void start()
    {
        while (true)
        {
            Message message = new Message();
            message.header.id = idStart++;
            message.header.qr = false; // This is a query.
            message.header.rd = false; // Recursion is not wanted.
            message.question = readQuestion();

            String nsZoneApex = "."; // The root domain name.
            IpAndPort ipAndPort = rootServer;
            String kskDigest = rootKskDigest;

            while (true)
            {
                // This also verifies that the server to which I'm connecting
                // is one of the valid nameservers for this zone.
                RSAPublicKey zsk = verifiedZskForZone(nsZoneApex, kskDigest,
                        ipAndPort);

                if (zsk == null)
                {
                    System.out.println("Aborting.");
                    break;
                }

                Message mAnswered = printFinalAnswer(message, ipAndPort, zsk);

                if (mAnswered == null)
                    break;
                else
                {
                    message.header.id = idStart++;
                    Rr ds = getDs(mAnswered);
                    kskDigest = ((RDataDs) ds.rData).digest;
                    nsZoneApex = ds.name;
                    ipAndPort = getRandomNameServer(mAnswered);
                }
            }
        }
    }

    // Return null if the message was answered or the answered message if a
    // redirect is needed.
    private Message printFinalAnswer(Message message, IpAndPort ipAndPort,
            RSAPublicKey zsk)
    {
        System.out.printf("Sending to %s (%s:%d) (%d B).\n\n%s\n",
                ipAndPort.name, ipAndPort.ipAddress.getHostAddress(),
                ipAndPort.port, message.toBytes().length, message);

        Message mAnswered = getAnswer(message, ipAndPort.ipAddress,
                ipAndPort.port);

        System.out.printf("Received from %s (%s:%d) (%d B).\n\n%s\n",
                ipAndPort.name, ipAndPort.ipAddress.getHostAddress(),
                ipAndPort.port, mAnswered.toBytes().length, mAnswered);

        // If a referral is needed.
        if (mAnswered.header.aa == false)
        {
            // Verify that the DS and the RRSIG exist and the RRSIG correctly
            // signed the DS.
            if (dsIsCorrect(mAnswered, zsk))
                System.out.println("The RRSIG for the DS is correct.");
            else
            {
                System.out.println("The RRSIG for the DS is incorrect. " +
                        "Aborting query.");
                return null;
            }

            System.out.println("Following the referral.");
            return mAnswered;
        }
        // The server says the name doesn't exist.
        else if (mAnswered.header.rcode == 3)
        {
            System.out.println("The name does not exist.");
            if (!validNonExistance(mAnswered, zsk))
            {
                System.out.println("Aborting.");
                return null;
            }
            System.out.println("The justification is valid.\n\n\n");
        }
        // The server says that there is no such data for that domain.
        else if (isNoDataError(mAnswered))
        {
            System.out.println("No such data for domain.");
            if (!validNoDataError(mAnswered, zsk))
            {
                System.out.println("Aborting.");
                return null;
            }
            System.out.println("The justification is valid.\n\n\n");
        }
        // The answer was given.
        else if (mAnswered.answer.size() > 0)
        {
            System.out.println("Got the answer.");
            if (!validAnswer(mAnswered, zsk))
            {
                System.out.println("Aborting.");
                return null;
            }
            System.out.println("The answer is valid.\n\n\n");
        }
        else
            System.out.println("Unknown problem. Aborting.\n\n\n");
        
        return null;
    }
    
    private MessageQuestion readQuestion()
    {
        MessageQuestion mq = new MessageQuestion();
        
        Scanner in = new Scanner(System.in);
        String[] split;

        while (true)
        {
            System.out.print("Query: ");
            String line = in.nextLine();
            boolean validQuery = true;


            if (line.equals("q") || line.equals("exit"))
            {
                System.out.println("Quitting.");
                System.exit(0);
            }

            split = line.split(" ");
            
            if (split.length != 2)
            {
                System.out.println("Correct query format: '<name> <type>'");
                validQuery = false;
                continue;
            }
            if (!Rr.typeCodeNumber.containsKey(split[1]))
            {
                System.out.println("That type isn't known.");
                validQuery = false;
            }
            if (split[0].charAt(split[0].length() - 1) != '.')
            {
                System.out.println("Domain name must end in a dot.");
                validQuery = false;
            }
            
            if (validQuery)
                break;
        }

        mq.qclass = "IN";
        mq.qname = split[0];
        mq.qtype = split[1];
        return mq;
    }

    private Message getAnswer(Message message, InetAddress address, int port)
    {
        try
        {
            byte[] sendData = message.toBytes();
            DatagramSocket clientSocket = new DatagramSocket();
            DatagramPacket sendPacket = new DatagramPacket(sendData,
                    sendData.length,
                    address,
                    port);
            clientSocket.send(sendPacket);
            byte[] buffer = new byte[AuthoritativeServer.BUF_SIZE];
            DatagramPacket receivePacket = new DatagramPacket(buffer,
                    buffer.length);
            clientSocket.receive(receivePacket);
            byte[] bytes = receivePacket.getData();
            Message mr = Message.fromBytes(Util.byteArrayList(bytes));
            clientSocket.close();
            return mr;
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            System.exit(1);
            return null; // Ca să nu se mai plângă Java.
        }
    }

    // Get the IP address and port of a random nameserver in the message.
    private IpAndPort getRandomNameServer(Message message)
    {
        IpAndPort ret = new IpAndPort();

        // List of name servers to pick from.
        ArrayList<String> nses = new ArrayList<String>();
        // Name to port.
        HashMap<String, Integer> ports = new HashMap<String, Integer>();
        for (Rr rr : message.authority)
            if (rr.type.equals("NS"))
            {
                RDataNs ns = (RDataNs) rr.rData;
                ports.put(ns.nsDName, ns.port);
                nses.add(ns.nsDName);
            }
        // Name to IP address.
        HashMap<String, String> ipAddresses = new HashMap<String, String>();
        for (Rr rr : message.additional)
            if (rr.type.equals("A"))
            {
                RDataA a = (RDataA) rr.rData;
                ipAddresses.put(rr.name, a.address);
            }

        String randomNs = nses.get(Util.randint(0, nses.size() - 1));
        try
        {
            ret.name = randomNs;
            ret.ipAddress = InetAddress.getByName(ipAddresses.get(randomNs));
            ret.port = ports.get(randomNs);
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            System.exit(1);
        }

        return ret;
    }

    private boolean isNoDataError(Message message)
    {
        for (Rr rr : message.authority)
            if (rr.type.equals("SOA"))
                return true;
        return false;
    }

    private Rr getDs(Message message)
    {
        for (Rr rr : message.authority)
            if (rr.type.equals("DS"))
                return rr;
        return null;
    }

    private boolean validNonExistance(Message message, RSAPublicKey zsk)
    {
        Rr soa = null;
        Rr soaRrSig = null;
        Rr nsec = null;
        Rr nsecRrSig = null;

        int size = message.authority.size();
        for (int i = 0; i < size; i++)
        {
            if (message.authority.get(i).type.equals("SOA"))
            {
                soa = message.authority.get(i);
                if (i + 1 < size &&
                        message.authority.get(i + 1).type.equals("RRSIG"))
                    soaRrSig = message.authority.get(i + 1);
            }
            else if(message.authority.get(i).type.equals("NSEC"))
            {
                nsec = message.authority.get(i);
                if (i + 1 < size &&
                        message.authority.get(i + 1).type.equals("RRSIG"))
                    nsecRrSig = message.authority.get(i + 1);
            }
        }

        if (soa == null)
        {
            System.out.println("No SOA was found.");
            return false;
        }
        if (soaRrSig == null)
        {
            System.out.println("The RRSIG for the SOA wasn't found.");
            return false;
        }
        if (!rrIsCorrect(soa, soaRrSig, zsk))
        {
            System.out.println("The SOA isn't correctly signed by the ZSK.");
            return false;
        }
        if (nsec == null)
        {
            System.out.println("No NSEC was found.");
            return false;
        }
        if (nsecRrSig == null)
        {
            System.out.println("The RRSIG for the NSEC wasn't found.");
            return false;
        }
        if (!rrIsCorrect(nsec, nsecRrSig, zsk))
        {
            System.out.println("The NSEC isn't correctly signed by the ZSK.");
            return false;
        }


        String a = nsec.name;
        String b = message.question.qname;
        String c = ((RDataNsec) nsec.rData).nextDomainName;
        String apexName = soa.name;
        DomainComparator comp = new DomainComparator();
        boolean valid = false;

        if (comp.compare(a, b) < 0 && comp.compare(b, c) < 0)
            valid = true;
        if (comp.compare(a, b) < 0 && c.equals(apexName))
            valid = true;

        if (!valid)
        {
            System.out.printf("'%s' isn't between '%s' and '%s'.\n", b, a, c);
            return false;
        }
        
        System.out.printf("'%s' is between '%s' and '%s'.\n", b, a, c);
        return true;
    }

    private boolean validNoDataError(Message message, RSAPublicKey zsk)
    {
        Rr nsec = null;
        Rr rrSig = null;

        int size = message.authority.size();
        for (int i = 0; i < size; i++)
        {
            if (message.authority.get(i).type.equals("NSEC"))
            {
                nsec = message.authority.get(i);
                if (i + 1 < size &&
                        message.authority.get(i + 1).type.equals("RRSIG"))
                    rrSig = message.authority.get(i + 1);
                break;
            }
        }

        if (nsec == null)
        {
            System.out.println("No NSEC was found.");
            return false;
        }
        if (rrSig == null)
        {
            System.out.println("The RRSIG for the NSEC doesn't exist.");
            return false;
        }
        if (!rrIsCorrect(nsec, rrSig, zsk))
        {
            System.out.println("The NSEC isn't correctly signed by the ZSK");
            return false;
        }
        if (!nsec.name.equals(message.question.qname))
        {
            System.out.println("This NSEC isn't for the domain for which I " +
                    "asked.");
            return false;
        }

        RDataNsec rData = (RDataNsec) nsec.rData;
        if (rData.getBitType(message.question.qtype))
        {
            System.out.printf("%s does exist '%s', but I wasn't given it.\n",
                    message.question.qtype, message.question.qname);
            return false;
        }

        System.out.printf("%s truly doesn't exist for domain '%s'.\n",
                message.question.qtype, message.question.qname);
        return true;
    }

    private boolean validAnswer(Message message, RSAPublicKey zsk)
    {
        int size = message.answer.size();

        if (size == 0)
        {
            System.out.println("The answer is empty.");
            return false;
        }

        for (int i = 0; i < size; i++)
        {
            if (message.answer.get(i).type.equals("A"))
            {
                Rr a = message.answer.get(i);
                if (i + 1 < size &&
                        message.answer.get(i + 1).type.equals("RRSIG"))
                {
                    Rr rrSig = message.answer.get(i + 1);
                    if (!rrIsCorrect(a, rrSig, zsk))
                    {
                        System.out.println("Signature isn't valid for: " + a);
                        return false;
                    }
                    else
                        System.out.println("Signature is valid for: " + a);
                }
                else
                {
                    System.out.println("This address isn't signed: " + a);
                    return false;
                }
            }
        }

        return true;
    }

    private boolean dsIsCorrect(Message message, RSAPublicKey zsk)
    {
        Rr ds = null;
        Rr rrSig = null;

        int size = message.authority.size();
        for (int i = 0; i < size; i++)
        {
            if (message.authority.get(i).type.equals("DS"))
            {
                ds = message.authority.get(i);
                if (i + 1 < size &&
                        message.authority.get(i + 1).type.equals("RRSIG"))
                    rrSig = message.authority.get(i + 1);
                break;
            }
        }

        if (ds == null)
        {
            System.out.println("No DS was found.");
            return false;
        }
        if (rrSig == null)
        {
            System.out.println("The RRSIG for it doesn't exist.");
            return false;
        }

        return rrIsCorrect(ds, rrSig, zsk);
    }

    private boolean rrIsCorrect(Rr rr, Rr rrSig, RSAPublicKey publicKey)
    {
        RDataRrSig rData = (RDataRrSig) rrSig.rData;
        byte[] bytes = Util.catBytes(rData.toBytesWithoutSignature(),
                rr.toBytes());
        String signature = rData.signature;

        return RSA.verify(bytes, signature, publicKey);
    }

    // Return null if the key cannot be trusted or if this is an incorrect
    // server for the zone.
    private RSAPublicKey verifiedZskForZone(String zone, String kskDigest,
            IpAndPort ipAndPort)
    {
        Message message = new Message();
        message.header.id = idStart++;
        message.header.qr = false; // This is a query.
        message.header.rd = false; // Recursion is not wanted.
        message.question = new MessageQuestion();
        message.question.qclass = "IN";
        message.question.qname = zone;
        message.question.qtype = "DNSKEY";

        System.out.printf("Detour, getting the DNSKEYs for '%s' from '%s':\n",
                zone, ipAndPort.name);

        Message mAnswered = getAnswer(message, ipAndPort.ipAddress,
                ipAndPort.port);

        System.out.println(mAnswered);

        Rr kskDnsKey = null;
        Rr zskDnsKey = null;
        Rr zskRrSig = null;

        int size = mAnswered.answer.size();
        for (int i = 0; i < size; i++)
        {
            Rr rr = mAnswered.answer.get(i);
            if (!rr.type.equals("DNSKEY"))
                continue;
            RDataDnsKey rData = (RDataDnsKey) rr.rData;
            if (rData.isSecureEntryPoint())
                kskDnsKey = rr;
            else
            {
                zskDnsKey = rr;
                if (i + 1 < size)
                    zskRrSig = mAnswered.answer.get(i + 1);
            }
        }

        if (kskDnsKey == null)
            System.out.println("There is no KSK DNSKEY");
        if (zskDnsKey == null)
            System.out.println("There is no ZSK DNSKEY");
        if (zskRrSig == null)
            System.out.println("There is no ZSK RRSIG");

        if (kskDnsKey == null || zskDnsKey == null || zskRrSig == null)
            return null;

        // Check that the KSK is the same one that the parent says it is.
        // First, compute the digest of the key.
        RDataDnsKey kskRData = (RDataDnsKey) kskDnsKey.rData;
        String computedKskDigest = SHA1.digest(Util.catBytes(
            Util.domainToBytes(kskDnsKey.name),
            kskRData.toBytes()
            ));

        System.out.printf("Computed KSK digest: %s\nCorrect KSK digest: %s\n",
                computedKskDigest, kskDigest);

        if (!computedKskDigest.equals(kskDigest))
        {
            System.out.println("The digest of the KSK isn't what the parent " +
                    "says it should be. Aborting.");
            return null;
        }

        RSAPublicKey ksk = RSA.publicKeyFromBytes(kskRData.publicKey);

        if (!rrIsCorrect(zskDnsKey, zskRrSig, ksk))
        {
            System.out.println("The ZSK isn't correctly signed by the KSK.");
            return null;
        }

        System.out.println("The ZSK is correctly signed by the KSK.");

        RDataDnsKey zskRData = (RDataDnsKey) zskDnsKey.rData;
        RSAPublicKey zsk = RSA.publicKeyFromBytes(zskRData.publicKey);

        // Now verify that server to which I connected is a valid one for this
        // zone.
        Rr ns = mAnswered.authority.get(0);
        Rr nsRrSig = mAnswered.authority.get(1);
        Rr a = mAnswered.additional.get(0);
        Rr aRrSig = mAnswered.additional.get(1);
        RDataNs nsRData = (RDataNs) ns.rData;
        RDataA aRData = (RDataA) a.rData;
        
        if (!ns.name.equals(zone))
        {
            System.out.println("This is not an NS for the zone.");
            return null;
        }
        if (!nsRData.nsDName.equals(a.name))
        {
            System.out.println("This is not an address for the nameserver.");
            return null;
        }
        if (!aRData.address.equals(ipAndPort.ipAddress.getHostAddress()))
        {
            System.out.println("This is not the address to which I connected.");
            return null;
        }
        if (!rrIsCorrect(ns, nsRrSig, zsk))
        {
            System.out.println("The NS isn't correctly signed by the ZSK.");
            return null;
        }
        if (!rrIsCorrect(a, aRrSig, zsk))
        {
            System.out.println("The A isn't correctly signed by the ZSK.");
            return null;
        }

        System.out.println("The NS and A corespond and the RRSIGs are " +
                "valid.\n");

        return zsk;
    }
}

class IpAndPort
{
    public String name;
    public InetAddress ipAddress;
    public int port;
}
