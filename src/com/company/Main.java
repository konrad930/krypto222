package com.company;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class Main{

    public static void main (String[] args)throws Exception {

        // wczytanie hasla
        System.out.println("Podaj haslo : ");
        BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
        String s = bufferRead.readLine();
        char pass[] = s.toCharArray(); //"konrad"
        Security.addProvider(new BouncyCastleProvider());

        //wczytanie keystora lub utworzenie nowego

        try{
            KeyStore ks = loadKeyStore(pass,args[1],args[2]);

            zgadnij(ks.getKey(args[2],pass));
            //oracle("AES/"+args[0]+"/PKCS5Padding",ks.getKey(args[2],pass));
            //challenge("AES/"+args[0]+"/PKCS5Padding",ks.getKey(args[2],pass));
        }
        catch (Exception e){
            System.out.print("Jakis blad");
        }
    }

    public static KeyStore loadKeyStore(char[]pass,String path,String keyId) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        KeyStore ks = KeyStore.getInstance("JCEKS");
        try {
            ks.load(new FileInputStream(path), pass);
        }catch (FileNotFoundException e){
            File file = new File(path);
            ks.load(null,null);
            SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();

            KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(pass);

            ks.setEntry(keyId, keyStoreEntry, keyPassword);
            ks.store(new FileOutputStream(file), pass);

            ks.load(new FileInputStream(file), pass);
        } catch (Exception e){}
        return ks;
    }


    public static void oracle(String algorytm,Key key) throws Exception{

        File folderM = new File("/Users/kgb/Desktop/M");
        File folderC = new File("/Users/kgb/Desktop/C");
        File folderD = new File("/Users/kgb/Desktop/D");

        File[] messages = folderM.listFiles();

        for(File file:messages)
            if(!file.getName().contains("DS_Store"))
                new AesCrypt(algorytm).encrypt(key, file, new File(folderC.getAbsolutePath() + "/" + file.getName() + ".enc"));

        File[] crypto = folderC.listFiles();

        for(File file:crypto)
            if(!file.getName().contains("DS_Store")){
                int length = file.getName().length()-4;
                new AesCrypt(algorytm).decrypt(key,file,new File(folderD.getAbsolutePath()+"/"+file.getName().substring(0,length)));
            }
    }

    public static void challenge(String algorytm,Key key){

        File[] messages = new File("/Users/kgb/Desktop/M").listFiles();
        File folderC = new File("/Users/kgb/Desktop/C");
        File folderD = new File("/Users/kgb/Desktop/D");

        for(int i=0;i<messages.length;i++)
            if(messages[i].getName().contains("DS_Store")) {
                messages[i].delete();
                break;
            }

        try {
            if(messages.length<2)
                throw new Exception("Za malo wiadomosci");

            int i = new Random().nextInt(1);

            File crypto = new File(folderC.getAbsolutePath() + "/" + messages[i].getName() + ".enc");

            new AesCrypt(algorytm).encrypt(key, messages[i],crypto);
            new AesCrypt(algorytm).decrypt(key,crypto,new File(
                    folderD.getAbsolutePath()+"/"+crypto.getName().substring(0,crypto.getName().length()-4)));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static File challenge(String algorytm,Key key,byte[]iv){

        File[] messages = new File("/Users/kgb/Desktop/M").listFiles();
        File folderC = new File("/Users/kgb/Desktop/C");
        File folderD = new File("/Users/kgb/Desktop/D");
        File crypto = null;

        for(int i=0;i<messages.length;i++)
            if(messages[i].getName().contains("DS_Store")) {
                messages[i].delete();
                break;
            }

        try {
            if(messages.length<2)
                throw new Exception("Za malo wiadomosci");

            int i = new Random().nextInt(2);

            crypto = new File(folderC.getAbsolutePath() + "/" + messages[i].getName() + ".enc");

            new AesCrypt(algorytm).encrypt(key, messages[i],crypto,iv);
            new AesCrypt(algorytm).decrypt(key,crypto,new File(
                    folderD.getAbsolutePath()+"/"+crypto.getName().substring(0,crypto.getName().length()-4)),iv);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return crypto;
    }

    public static void zgadnij(Key key)throws Exception{

        byte[] iv0 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1 };
        byte[] iv1 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0 };

        File m0 = new File("/Users/kgb/Desktop/M/m0.txt");
        File m1 = new File("/Users/kgb/Desktop/M/m1.txt");
        File d =  new File("/Users/kgb/Desktop/D/d0.txt");
        File c0 = new File("/Users/kgb/Desktop/C/c0.enc");

        int x = new Random().nextInt(2);

        if(x ==0)
            new AesCrypt("AES/CBC/PKCS5Padding").encrypt(key, m0,c0,iv0);
        else
            new AesCrypt("AES/CBC/PKCS5Padding").encrypt(key, m1,c0,iv0);

        new AesCrypt("AES/CBC/PKCS5Padding").decrypt(key, c0, d, iv0);


        byte[] m0Arr = new byte[16];
        byte[] m2Arr = new byte[16];

        InputStream is = new FileInputStream(m0);
        is.read(m0Arr);
        is.close();

        for(int i=0;i<16;i++)
            m2Arr[i] = (byte)(iv0[i]^iv1[i]^m0Arr[i]);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv1));

        FileOutputStream fos = new FileOutputStream("/Users/kgb/Desktop/M/m2.txt");
        fos.write(m2Arr);
        fos.close();

        new AesCrypt("AES/CBC/PKCS5Padding").encrypt(key,
                new File("/Users/kgb/Desktop/M/m2.txt"),new File("/Users/kgb/Desktop/C/c1"),iv1);

        byte[] c1Arr = new byte[16];
        byte[] c0Arr = new byte[16];

        is = new FileInputStream(new File("/Users/kgb/Desktop/C/c1"));
        is.read(c1Arr);
        is.close();

        is = new FileInputStream(c0);
        is.read(c0Arr);
        is.close();

        if(Arrays.equals(c0Arr,c1Arr) && x == 0)
            System.out.println("First message was encrypted");
        else if(!Arrays.equals(c0Arr,c1Arr) && x == 1)
            System.out.println("Second message was encrypted");
        else
            System.out.println("Error");

    }

    private static byte[] encryptMessage(byte[] message, Key key, byte[] iv) throws Exception{

        byte[] everything = message;
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = (cipher.doFinal(everything));

        try {
            FileOutputStream fop = new FileOutputStream(new File("/Users/kgb/Desktop/C"));
            fop.write(encrypted);
            fop.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;
    }




}

