package net.nechifor.dnssec_toy.logic;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Scanner;
import javax.xml.bind.DatatypeConverter;
import net.nechifor.dnssec_toy.data.RDataDnsKey;
import net.nechifor.dnssec_toy.data.RDataDs;
import net.nechifor.dnssec_toy.data.RDataNsec;
import net.nechifor.dnssec_toy.data.RDataRrSig;
import net.nechifor.dnssec_toy.data.Rr;
import net.nechifor.dnssec_toy.util.Util;

public class CreateAndSign
{
    private File file;
    
    private String apexName;

    private ArrayList<Rr> rrs;

    private String kskPrivate64;
    private String kskPublic64;
    private String zskPrivate64;
    private String zskPublic64;

    private RSAPrivateKey kskPrivate;
    private RSAPublicKey kskPublic;
    private RSAPrivateKey zskPrivate;
    private RSAPublicKey zskPublic;

    private int kskKeyTag;
    private int zskKeyTag;

    public CreateAndSign(File file)
    {
        this.file = file;
    }
    public void start()
    {
        loadMasterFile();
        loadKeyPairs();
        getApexName();

        createDnsKeys();
        createDses();
        
        // This operation needs to be done before the previous two because it
        // needs to know the types available for a certain domain name.
        // It adds RRSIG automatically, because one will be created after this.
        createNsecs();

        sortRrs();

        createRrSigs();
        writeSignedMasterFile();

        if (apexName.equals("."))
            printDigestForRootKsk();
    }

    private void loadMasterFile()
    {
        if (!file.exists())
        {
            System.err.println("Master file '" + file.getPath() +
                    "' doesn't exit.");
            System.exit(1);
        }

        rrs = Rr.loadFromFile(file);


    }

    private void getApexName()
    {
        for (Rr rr : rrs)
            if (rr.type.equals("SOA"))
            {
                apexName = rr.name;
                break;
            }
        if (apexName == null)
        {
            System.err.println("There is no SOA in '" + file.getPath() + "'.");
            System.exit(1);
        }
    }

    private void loadKeyPairs()
    {

        File keyFile = new File(file.getParentFile(),
                "keypairs_" + file.getName());

        if (!keyFile.exists())
        {
            System.err.println("Key file '" + keyFile.getPath() +
                    "' doesn't exit. Use `--genkeypair` to generate it.");
            System.exit(1);
        }

        try
        {
            Scanner in = new Scanner(keyFile);
            kskPrivate64 = in.nextLine().trim();
            kskPublic64 = in.nextLine().trim();
            zskPrivate64 = in.nextLine().trim();
            zskPublic64 = in.nextLine().trim();
            in.close();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            System.exit(1);
        }

        kskPrivate = RSA.privateKeyFromBytes(
                DatatypeConverter.parseBase64Binary(kskPrivate64));
        kskPublic = RSA.publicKeyFromBytes(
                DatatypeConverter.parseBase64Binary(kskPublic64));
        zskPrivate = RSA.privateKeyFromBytes(
                DatatypeConverter.parseBase64Binary(zskPrivate64));
        zskPublic = RSA.publicKeyFromBytes(
                DatatypeConverter.parseBase64Binary(zskPublic64));
    }

    private void createDnsKeys()
    {
        // The Zone Signing Key (public).
        Rr rr = new Rr();
        rr.name = apexName;
        rr.type = "DNSKEY";
        rr.theClass = "IN";
        rr.ttl = 86400;
        RDataDnsKey rData = new RDataDnsKey();
        rData.flags = 256; // Sets the Zone Key bit.
        rData.protocol = 3; // 3 is the only possible value.
        rData.algorithm = 5; // I've only implemented 5 (RSA/SHA-1).
        rData.publicKey = DatatypeConverter.parseBase64Binary(zskPublic64);
        rr.rData = rData;
        rrs.add(rr);

        zskKeyTag = rData.calculateKeyTag();

        // The Key Signing Key (public).
        rr = new Rr();
        rr.name = apexName;
        rr.type = "DNSKEY";
        rr.theClass = "IN";
        rr.ttl = 86400;
        rData = new RDataDnsKey();
        rData.flags = 257; // Sets the Zone Key bit and the SEP bit.
        rData.protocol = 3; // 3 is the only possible value.
        rData.algorithm = 5; // I've only implemented 5 (RSA/SHA-1).
        rData.publicKey = DatatypeConverter.parseBase64Binary(kskPublic64);
        rr.rData = rData;
        rrs.add(rr);

        kskKeyTag = rData.calculateKeyTag();
    }

    private void createDses()
    {
        // First we need to find out what are de delegation points.
        HashSet<String> subZones = new HashSet<String>();

        // Load glue RRs if they exist.
        // If the zone is "ro." the glue should be in "glue_zone_ro".
        File glueFile = new File(file.getParentFile(),
                "glue_zone_" + apexName.substring(0, apexName.length() - 1));

        if (!glueFile.exists())
            return; // No point in continuing.
        
        ArrayList<Rr> glueRrs = Rr.loadFromFile(glueFile);

        for (Rr rr : glueRrs)
            if (rr.type.equals("NS") && !rr.name.equals(apexName))
                subZones.add(rr.name);

        // Now we read the keypairs file which has to be in the same directory
        // for the subzone.
        for (String zone : subZones)
        {
            String key64 = getPublicKskForZone(zone);
            // I need to make the RData of the DNSKEY of the key because the key
            // tag is computed from it.
            RDataDnsKey key = new RDataDnsKey();
            key.flags = 257; // Sets the Zone Key bit and the SEP bit.
            key.protocol = 3; // 3 is the only possible value.
            key.algorithm = 5; // I've only implemented 5 (RSA/SHA-1).
            key.publicKey = DatatypeConverter.parseBase64Binary(key64);

            Rr rr = new Rr();
            rr.name = zone;
            rr.type = "DS";
            rr.theClass = "IN";
            rr.ttl = 86400;
            RDataDs rData = new RDataDs();
            rData.keyTag = key.calculateKeyTag();
            rData.algorithm = 5; // I've only implemented 5 (RSA/SHA-1).
            rData.digestType = 1; // SHA-1
            rData.digest = SHA1.digest(Util.catBytes(
                    Util.domainToBytes(zone),
                    key.toBytes()
                    ));
            rr.rData = rData;

            rrs.add(rr);
        }
    }

    private void printDigestForRootKsk()
    {
        String key64 = getPublicKskForZone(".");
        // I need to make the RData of the DNSKEY of the key because the key
        // tag is computed from it.
        RDataDnsKey key = new RDataDnsKey();
        key.flags = 257; // Sets the Zone Key bit and the SEP bit.
        key.protocol = 3; // 3 is the only possible value.
        key.algorithm = 5; // I've only implemented 5 (RSA/SHA-1).
        key.publicKey = DatatypeConverter.parseBase64Binary(key64);
        String digest = SHA1.digest(Util.catBytes(
                Util.domainToBytes("."),
                key.toBytes()
                ));
        System.out.println("Root KSK digest: " + digest);
    }

    private void createNsecs()
    {
        ArrayList<Rr> nsecs = new ArrayList<Rr>();

        HashSet<String> domainsSet = new HashSet<String>();

        for (Rr rr : rrs)
            domainsSet.add(rr.name);

        // It's just Java being weird.
        String[] domains = domainsSet.toArray(new String[0]);
        Arrays.sort(domains, new DomainComparator());

        for (int i = 0; i < domains.length; i++)
        {
            Rr rr = new Rr();
            rr.name = domains[i];
            rr.type = "NSEC";
            rr.theClass = "IN";
            rr.ttl = 86400;
            RDataNsec rDataNsec = new RDataNsec();

            if (i + 1 < domains.length)
                rDataNsec.nextDomainName = domains[i + 1];
            else
                rDataNsec.nextDomainName = domains[0];

            for (String type : getTypesForDomain(domains[i]))
                rDataNsec.setBitType(type, true);
	    // Set it even though it hasn't been created because it will be
	    // created after.
	    rDataNsec.setBitType("RRSIG", true);

            rr.rData = rDataNsec;

            nsecs.add(rr);
        }

        rrs.addAll(nsecs);
    }

    private void sortRrs()
    {
        final DomainComparator domainComparator = new DomainComparator();

        // Sort them by domain name.
        Collections.sort(rrs, new Comparator()
        {
            public int compare(Object a, Object b)
            {
                return domainComparator.compare(((Rr) a).name, ((Rr) b).name);
            }
        });
    }

    private void createRrSigs()
    {
        ArrayList<Rr> newRrs = new ArrayList<Rr>();

        for (Rr rr : rrs)
        {
            newRrs.add(rr);

            Rr srr = new Rr();
            srr.name = rr.name;
            srr.type = "RRSIG";
            srr.theClass = "IN";
            srr.ttl = rr.ttl;

            RDataRrSig rData = new RDataRrSig();
            rData.typeCovered = rr.type;
            rData.algorithm = 5; // I've only implemented 5 (RSA/SHA-1).
            rData.originalTtl = rr.ttl;
            rData.signatureInception = System.currentTimeMillis() / 1000;
            rData.signatureExpiration = rData.signatureInception + rr.ttl;
            if (rr.type.equals("DNSKEY"))
                rData.keyTag = kskKeyTag;
            else
                rData.keyTag = zskKeyTag;
            rData.signersName = apexName;
            if (rr.type.equals("DNSKEY"))
                rData.setSignatureWith(rr, kskPrivate);
            else
                rData.setSignatureWith(rr, zskPrivate);
            srr.rData = rData;

            newRrs.add(srr);
        }

        rrs = newRrs;
    }

    private void writeSignedMasterFile()
    {
        // Calculate field maximums to display them in columns.
        int maxName = 0;
        int maxType = 0;
        int maxClass = 0;
        int maxTtl = 0;
        for (Rr rr : rrs)
        {
            if (rr.name.length() > maxName)
                maxName = rr.name.length();
            if (rr.type.length() > maxType)
                maxType = rr.type.length();
            if (rr.theClass.length() > maxClass)
                maxClass = rr.theClass.length();
            String n = new Long(rr.ttl).toString();
            if (n.length() > maxTtl)
                maxTtl = n.length();
        }

        File signedMasterFile = new File(file.getParentFile(),
                "signed_" + file.getName());

        try
        {
            FileWriter writer = new FileWriter(signedMasterFile);
            PrintWriter printer = new PrintWriter(writer);

            for (Rr rr : rrs)
            {
                printer.print(Util.padRight(rr.name, maxName + 1));
                printer.print(Util.padRight(rr.type, maxType + 1));
                printer.print(Util.padRight(rr.theClass, maxClass + 1));
                printer.print(Util.padRight(new Long(rr.ttl).toString(),
                        maxTtl + 1));
                printer.print(rr.rData.toString() + "\n");
            }

            printer.close();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private short numberOfLabels(String domain)
    {
        if (domain.equals("."))
            return 0;

        short n = 0;
        int size = domain.length();
        for (int i = 0; i < size; i++)
            if (domain.charAt(i) == '.')
                n++;

        return n;
    }

    private ArrayList<String> getTypesForDomain(String domain)
    {
        HashSet<String> types = new HashSet<String>();

        for (Rr rr : rrs)
            if (rr.name.equals(domain))
                types.add(rr.type);

        ArrayList<String> ret = new ArrayList<String>();

        for (String type : types)
            ret.add(type);

        return ret;
    }

    private String getPublicKskForZone(String zone)
    {

        // If the zone is "com.ro." the key should be in "keypairs_zone_com.ro".
        File keyFile = new File(file.getParentFile(),
                "keypairs_zone_" + zone.substring(0, zone.length() - 1));

        if (!keyFile.exists())
        {
            System.err.println("Key file '" + keyFile.getPath() +
                    "' doesn't exit. Use `--genkeypair` to generate it.");
            System.exit(1);
        }

        String ret = null;

        try
        {
            Scanner in = new Scanner(keyFile);
            in.nextLine().trim(); // Discard the first key (the private one).
            ret = in.nextLine().trim();
            in.close();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            System.exit(1);
        }

        return ret;
    }
}
