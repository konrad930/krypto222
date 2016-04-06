package com.company;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;

/* Szyfrowanie plikow algorytmem AES przykladowa tablica argumentow
 * CTR D:/krypto/Lista3/mykeystore.bks mykey2 -e Alarm.wav Alarm2.wav.enc
 * CTR D:/krypto/Lista3/mykeystore.bks mykey2 -d Alarm2.wav.enc Alarm3.wav
 *
 * Created by kgb on 02.04.2016.
 */
public class AesCrypt {

    private String algorytm;

    public AesCrypt(String algorytm) {
        this.algorytm=algorytm;
    }

    public void encrypt(Key key,File in,File out) throws Exception{

        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher encrypt =  Cipher.getInstance(algorytm,"BC");

        if(algorytm.split("/")[1].equals("ECB"))
            encrypt.init(Cipher.ENCRYPT_MODE, key);
        else
            encrypt.init(Cipher.ENCRYPT_MODE, key,ivspec);

        FileInputStream fis =new FileInputStream(in);
        CipherOutputStream cos =new CipherOutputStream(new FileOutputStream(out), encrypt);

        byte[] buf = new byte[1024];
        int read;

        while((read=fis.read(buf))!=-1)
            cos.write(buf,0,read);

        cos.close();
        fis.close();
    }

    public void encrypt(Key key,File in,File out,byte[] iv) throws Exception{

        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher encrypt =  Cipher.getInstance(algorytm,"BC");

        if(algorytm.split("/")[1].equals("ECB"))
            encrypt.init(Cipher.ENCRYPT_MODE, key);
        else
            encrypt.init(Cipher.ENCRYPT_MODE, key,ivspec);

        FileInputStream fis =new FileInputStream(in);
        CipherOutputStream cos =new CipherOutputStream(new FileOutputStream(out), encrypt);

        byte[] buf = new byte[1024];
        int read;

        while((read=fis.read(buf))!=-1)
            cos.write(buf,0,read);

        cos.close();
        fis.close();
    }

    public void decrypt(Key key,File in,File out,byte[] iv) throws Exception{

        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher decrypt =  Cipher.getInstance(algorytm,"BC");

        if(algorytm.split("/")[1].equals("ECB"))
            decrypt.init(Cipher.DECRYPT_MODE, key);
        else
            decrypt.init(Cipher.DECRYPT_MODE,key,ivspec);

        FileOutputStream fos =new FileOutputStream(out);
        CipherInputStream cin=new CipherInputStream(new FileInputStream(in), decrypt);

        byte[] buf = new byte[1024];
        int read;

        while((read=cin.read(buf))!=-1)
            fos.write(buf,0,read);

        cin.close();
        fos.close();
    }

    public void decrypt(Key key,File in,File out) throws Exception{

        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher decrypt =  Cipher.getInstance(algorytm,"BC");

        if(algorytm.split("/")[1].equals("ECB"))
            decrypt.init(Cipher.DECRYPT_MODE, key);
        else
            decrypt.init(Cipher.DECRYPT_MODE,key,ivspec);

        FileOutputStream fos =new FileOutputStream(out);
        CipherInputStream cin=new CipherInputStream(new FileInputStream(in), decrypt);

        byte[] buf = new byte[1024];
        int read;

        while((read=cin.read(buf))!=-1)
            fos.write(buf,0,read);

        cin.close();
        fos.close();
    }




}
