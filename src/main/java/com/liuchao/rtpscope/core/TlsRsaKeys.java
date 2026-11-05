package com.liuchao.rtpscope.core;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.*;
import java.util.regex.*;
import javax.crypto.Cipher;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.*;

/** Unencrypted PKCS#1/PKCS#8 RSA private keys, retained only in the analysis session. */
public final class TlsRsaKeys {
    private static final int MAX_BYTES=1024*1024,MAX_KEYS=32;
    private final List<RSAPrivateCrtKey> keys;
    private TlsRsaKeys(List<RSAPrivateCrtKey> keys){this.keys=Collections.unmodifiableList(keys);}
    public static TlsRsaKeys empty(){return new TlsRsaKeys(new ArrayList<>());}
    public int size(){return keys.size();}
    public static TlsRsaKeys read(InputStream input)throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[4096];int n;
        while((n=input.read(buffer))!=-1){if(out.size()+n>MAX_BYTES)throw new IOException("RSA 私钥文件超过 1 MiB");out.write(buffer,0,n);}
        byte[] bytes=out.toByteArray();String text=new String(bytes,StandardCharsets.US_ASCII);
        if(text.contains("ENCRYPTED")||text.contains("Proc-Type:"))throw new IOException("RSA 私钥已加密；当前支持未加密的 PKCS#1 / PKCS#8 私钥，请在本地导出对应格式后导入");
        if(text.contains("CLIENT_RANDOM ")||text.contains("TRAFFIC_SECRET"))throw new IOException("这是 TLS key log，请选择「导入 TLS key log」");
        List<RSAPrivateCrtKey> keys=new ArrayList<>();
        try {
            if(text.contains("-----BEGIN ")){
                Matcher pem=Pattern.compile("-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----([\\s\\S]*?)-----END \\1-----").matcher(text);
                while(pem.find()){
                    byte[] der=Base64.getDecoder().decode(pem.group(2).replaceAll("\\s", ""));
                    add(keys,parse(der,pem.group(1).equals("PRIVATE KEY")));
                }
                if(keys.isEmpty())throw new IOException("未找到 RSA 私钥；证书、公钥和非 RSA 私钥不能用于此入口");
            }else{
                ASN1Sequence sequence=ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(bytes));
                add(keys,parse(bytes,sequence.size()>1&&sequence.getObjectAt(1).toASN1Primitive() instanceof ASN1Sequence));
            }
        }catch(IOException|GeneralSecurityException|RuntimeException e){throw new IOException("RSA 私钥格式无效；需要未加密 PEM / DER 的 PKCS#1 / PKCS#8 RSA 私钥，证书或公钥不能代替");}
        return new TlsRsaKeys(keys);
    }
    private static RSAPrivateCrtKey parse(byte[] der,boolean pkcs8)throws IOException,GeneralSecurityException {
        try {
            ASN1Primitive object=ASN1Primitive.fromByteArray(der);
            if(pkcs8){PrivateKeyInfo info=PrivateKeyInfo.getInstance(object);if(!info.getPrivateKeyAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption))throw new IOException("该文件不是用于 RSA 密钥交换的 RSA 私钥");object=info.parsePrivateKey().toASN1Primitive();}
            org.bouncycastle.asn1.pkcs.RSAPrivateKey key=org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(object);
            BigInteger p=key.getPrime1(),q=key.getPrime2(),e=key.getPublicExponent(),d=key.getPrivateExponent(),mod=key.getModulus();
            if(!key.getVersion().equals(BigInteger.ZERO)||mod.bitLength()<512||mod.bitLength()>16384||p.signum()<=0||q.signum()<=0||e.signum()<=0||d.signum()<=0||!p.multiply(q).equals(mod))throw new GeneralSecurityException();
            BigInteger pm=p.subtract(BigInteger.ONE),qm=q.subtract(BigInteger.ONE),lambda=pm.divide(pm.gcd(qm)).multiply(qm);
            if(!d.multiply(e).mod(lambda).equals(BigInteger.ONE)||!d.mod(pm).equals(key.getExponent1())||!d.mod(qm).equals(key.getExponent2())||!q.multiply(key.getCoefficient()).mod(p).equals(BigInteger.ONE))throw new GeneralSecurityException();
            return (RSAPrivateCrtKey)KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(mod,e,d,p,q,key.getExponent1(),key.getExponent2(),key.getCoefficient()));
        }catch(IllegalArgumentException|ArithmeticException e){throw new GeneralSecurityException();}
    }
    private static void add(List<RSAPrivateCrtKey> keys,RSAPrivateCrtKey key)throws IOException {
        for(RSAPrivateCrtKey existing:keys)if(existing.getModulus().equals(key.getModulus())&&existing.getPublicExponent().equals(key.getPublicExponent()))return;
        if(keys.size()>=MAX_KEYS)throw new IOException("RSA 私钥最多加载 32 把");keys.add(key);
    }
    public TlsRsaKeys merge(TlsRsaKeys other)throws IOException {List<RSAPrivateCrtKey> combined=new ArrayList<>(keys);for(RSAPrivateCrtKey key:other.keys)add(combined,key);return new TlsRsaKeys(combined);}
    boolean matches(RSAPublicKey server){for(RSAPrivateCrtKey key:keys)if(matches(key,server))return true;return false;}
    private static boolean matches(RSAPrivateCrtKey key,RSAPublicKey server){return key.getModulus().equals(server.getModulus())&&key.getPublicExponent().equals(server.getPublicExponent());}
    byte[] premaster(byte[] encrypted,RSAPublicKey server,int clientVersion)throws GeneralSecurityException {
        for(RSAPrivateCrtKey key:keys){
            if(server!=null&&!matches(key,server)||encrypted.length!=(key.getModulus().bitLength()+7)/8)continue;
            byte[] plain=null;
            try{Cipher rsa=Cipher.getInstance("RSA/ECB/PKCS1Padding");rsa.init(Cipher.DECRYPT_MODE,key);plain=rsa.doFinal(encrypted);if(plain.length==48&&((plain[0]&255)<<8|(plain[1]&255))==clientVersion)return plain;}catch(GeneralSecurityException ignored){}
            if(plain!=null)Arrays.fill(plain,(byte)0);
        }
        throw new GeneralSecurityException();
    }
}
