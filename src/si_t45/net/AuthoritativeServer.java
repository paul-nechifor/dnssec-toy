package si_t45.net;

import java.io.File;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.ArrayList;
import java.util.HashSet;
import si_t45.data.Message;
import si_t45.data.RDataMx;
import si_t45.data.RDataNs;
import si_t45.data.RDataNsec;
import si_t45.data.Rr;
import si_t45.logica.DomainComparator;
import si_t45.util.Util;

public class AuthoritativeServer
{
    public final static int BUF_SIZE = 2048;
    private String nsName; // The domain of the current name server.
    private int port;
    private File masterFile;
    private ArrayList<Rr> rrs;
    private ArrayList<Rr> mySoa = new ArrayList<Rr>();
    private ArrayList<Rr> myAuthority = new ArrayList<Rr>();
    private String apexName;
    private HashSet<String> subzones = new HashSet<String>();

    public AuthoritativeServer(String name, int port, File masterFile)
    {
        this.nsName = name;
        this.port = port;
        this.masterFile = masterFile;
        // It is assumed that the rrs are sorted by domain name in cannonical
        // order and the RRSIGs are always right after the coresponing RR.
        this.rrs = Rr.loadFromFile(masterFile);

        int size = rrs.size();
        for (int i = 0; i < size; i++)
        {
            Rr rr = rrs.get(i);
            if (rr.type.equals("SOA"))
            {
                mySoa.add(rr);
                mySoa.add(rrs.get(i + 1)); // Right after is the RRSIG.
                apexName = rr.name;
            }
            if (rr.type.equals("DS"))
                subzones.add(rr.name);

            if (rr.type.equals("NS") &&
                    ((RDataNs)rr.rData).nsDName.equals(name))
            {
                myAuthority.add(rr);
                myAuthority.add(rrs.get(i + 1)); // Right after is the RRSIG.
            }
        }

        if (mySoa.isEmpty())
        {
            System.err.println("There is no SOA!");
            System.exit(1);
        }
        if (myAuthority.isEmpty())
        {
            System.err.println("Where's my authority?");
            System.exit(1);
        }

        // Load glue RR if they exist.
        // If the zone is "ro." the glue should be in "glue_zone_ro".
        File glueFile = new File(masterFile.getParentFile(),
                "glue_zone_" + apexName.substring(0, apexName.length() - 1));

        if (glueFile.exists())
            rrs.addAll(Rr.loadFromFile(glueFile));
    }

    public void start() throws Exception
    {
        DatagramSocket serverSocket = new DatagramSocket(port);
        byte[] buffer = new byte[BUF_SIZE];

        System.out.printf("Started server %s on port %d with '%s'.\n", nsName,
                port, masterFile);

        while (true)
        {
            DatagramPacket receivePacket =
                    new DatagramPacket(buffer, buffer.length);
            serverSocket.receive(receivePacket);

            byte[] bytes = receivePacket.getData();
            Message message = Message.fromBytes(Util.byteArrayList(bytes));
            System.out.println("Got query:\n" + message);
            answerMessage(message);
            System.out.println("Will send:\n" + message);
            byte[] answeredBytes = message.toBytes();

            DatagramPacket sendPacket = new DatagramPacket(
                    answeredBytes,
                    answeredBytes.length,
                    receivePacket.getAddress(),
                    receivePacket.getPort());
            serverSocket.send(sendPacket);
        }
    }

    private void answerMessage(Message message)
    {
        message.header.ra = false; // No recursion is available.
        message.header.aa = true; // It is authoritative.
        message.header.qr = true; // This is a response.

        ArrayList<Rr> found = findRrs(message.question.qname,
                message.question.qtype);

        if (!found.isEmpty())
        {
            message.answer = found;
            addAnswerAdditional(message);
            addMyAuthority(message);
            addAuthorityAdditional(message);
        }
        else
        {
            String subzone = findReferral(message.question.qname);

            if (subzone != null)
            {
                message.header.aa = false; // It is a referral, so it's not AA.
                addReferralTo(message.authority, subzone);
                addAuthorityAdditional(message);
            }
            else
            {
                // If this domain does exist then this is a No Data Error.
                if (domainExists(message.question.qname))
                    message.header.rcode = 0;
                else
                    message.header.rcode = 3; // 3 = Name Error
                
                addSoa(message);
                addNameErrorNsec(message, message.question.qname);
            }
        }
    }

    private boolean domainExists(String domain)
    {
        for (Rr rr : rrs)
            if (rr.name.equals(domain))
                return true;
        return false;
    }

    private ArrayList<Rr> findRrs(String name, String type)
    {
        ArrayList<Rr> ret = new ArrayList<Rr>();

        int size = rrs.size();

        for (int i = 0; i < size; i++)
        {
            Rr rr = rrs.get(i);
            if (rr.name.equals(name) && rr.type.equals(type))
            {
                ret.add(rr);
                if (i + 1 < size && rrs.get(i+1).type.equals("RRSIG"))
                    ret.add(rrs.get(i+1));
            }
        }

        return ret;
    }

    private String findReferral(String name)
    {
        while (true)
        {
            // Remove labels from the begining until we find the subzone or
            // the name becomes "".
            int index = name.indexOf(".");
            name = name.substring(index + 1);

            if (name.equals(""))
                return null;

            if (subzones.contains(name))
                return name;
        }
    }

    private void addReferralTo(ArrayList<Rr> list, String domain)
    {
        // Add the NSes for this zone.
        for (Rr rr : rrs)
            if (rr.type.equals("NS") && rr.name.equals(domain))
            {
                list.add(rr);
                System.out.println(">>>" + rr);
            }
                

        // Add the DS and RRSIG for it.
        int size = rrs.size();
        for (int i = 0; i < size; i++)
            if (rrs.get(i).type.equals("DS") && rrs.get(i).name.equals(domain))
            {
                list.add(rrs.get(i));
                if (i + 1 < size)
                    list.add(rrs.get(i + 1));
                break;
            }
    }

    private void addAnswerAdditional(Message message)
    {
        addAdditional(message, message.answer);
    }

    private void addAuthorityAdditional(Message message)
    {
        addAdditional(message, message.authority);
    }

    private void addAdditional(Message message, ArrayList<Rr> from)
    {
        for (Rr rr : from)
        {
            ArrayList<Rr> found = new ArrayList<Rr>();
            if (rr.type.equals("MX"))
                found = findRrs(((RDataMx)rr.rData).exchange, "A");
            else if (rr.type.equals("NS"))
                found = findRrs(((RDataNs)rr.rData).nsDName, "A");

            message.additional.addAll(found);
        }
    }

    private void addMyAuthority(Message message)
    {
        message.authority.addAll(myAuthority);
    }

    private void addSoa(Message message)
    {
        message.authority.addAll(mySoa);
    }

    private void addNameErrorNsec(Message message, String domain)
    {
        // Search for the NSEC for which points to a domain that is greather
        // than the one in the parameter or it is the apex name (i.e. the last
        // NSEC).

        DomainComparator domainComparator = new DomainComparator();
        int size = rrs.size();
        for (int i = 0; i < size; i++)
        {
            if (rrs.get(i).type.equals("NSEC"))
            {
                String next = ((RDataNsec)rrs.get(i).rData).nextDomainName;
                if (domainComparator.compare(domain, next) < 0 ||
                        next.equals(apexName))
                {
                    message.authority.add(rrs.get(i));
                    message.authority.add(rrs.get(i + 1)); // The RRSIG for it.
                    break;
                }
            }
        }
    }
}
