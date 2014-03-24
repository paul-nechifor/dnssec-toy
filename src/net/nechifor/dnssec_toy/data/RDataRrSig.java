package net.nechifor.dnssec_toy.data;

import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import javax.xml.bind.DatatypeConverter;
import net.nechifor.dnssec_toy.logic.RSA;
import net.nechifor.dnssec_toy.util.Util;

public class RDataRrSig extends RData
{
    public String typeCovered;
    public short algorithm;
    public short labels;
    public long originalTtl;
    public long signatureExpiration;
    public long signatureInception;
    public int keyTag;
    public String signersName;
    public String signature; // In base 64.

    public RDataRrSig()
    {
    }

    public RDataRrSig(String s)
    {
        String[] split = s.split(" ");
        typeCovered = split[0];
        algorithm = Short.parseShort(split[1]);
        labels = Short.parseShort(split[2]);
        originalTtl = Long.parseLong(split[3]);
        signatureExpiration = Long.parseLong(split[4]);
        signatureInception = Long.parseLong(split[5]);
        keyTag = Integer.parseInt(split[6]);
        signersName = split[7];
        signature = split[8];
    }

    public static RDataRrSig fromBytes(ArrayList<Byte> b)
    {
        RDataRrSig ret = new RDataRrSig();

        ret.typeCovered = Rr.typeCodeString.get(
                Util.getShortFromByteArrayList(b));
        ret.algorithm = Util.getByteFromByteArrayList(b);
        ret.labels = Util.getByteFromByteArrayList(b);
        ret.originalTtl = Util.getIntFromByteArrayList(b);
        ret.signatureExpiration = Util.getIntFromByteArrayList(b);
        ret.signatureInception = Util.getIntFromByteArrayList(b);
        ret.keyTag = Util.getShortFromByteArrayList(b);
        ret.signersName = Util.getDomainFromByteArrayList(b);
        ret.signature = DatatypeConverter.printBase64Binary(Util.byteArray(b));

        return ret;
    }

    @Override
    public String toString()
    {
        return typeCovered + " " + algorithm + " " + labels + " " +
                originalTtl + " " + signatureExpiration + " " +
                signatureInception + " " + keyTag + " " + signersName + " " +
                signature;
    }

    @Override
    public byte[] toBytes()
    {
        return Util.catBytes(
                toBytesWithoutSignature(),
                DatatypeConverter.parseBase64Binary(signature)
                );
    }

    public byte[] toBytesWithoutSignature()
    {
        return Util.catBytes(
                Util.shortToBytes(Rr.typeCodeNumber.get(typeCovered)),
                Util.byteToBytes(algorithm),
                Util.byteToBytes(labels),
                Util.intToBytes(originalTtl),
                Util.intToBytes(signatureExpiration),
                Util.intToBytes(signatureInception),
                Util.shortToBytes(keyTag),
                Util.domainToBytes(signersName)
                );
    }

    public void setSignatureWith(Rr rr, RSAPrivateKey privateKey)
    {
        byte[] bytes = Util.catBytes(toBytesWithoutSignature(), rr.toBytes());
        signature = RSA.sign(bytes, privateKey);
    }
}
