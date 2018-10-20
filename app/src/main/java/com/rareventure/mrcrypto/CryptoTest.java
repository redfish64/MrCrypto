package com.rareventure.mrcrypto;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;

public class CryptoTest extends AppCompatActivity {
    public static String TAG = "MrCrypto";

    private static final int SALT_LENGTH = 32;

    private static byte[] salt;
    private static String log="";

    private String [][] encSchemes =
            {
                    { "AES", "AES/CBC/PKCS5Padding"},
                    { "AES", "AES/CBC/PKCS7Padding"},
                    { "AES", "AES/CBC/NoPadding"},
                    { "AES", "AES/GCM/PKCS5Padding"},
                    { "AES", "AES/GCM/PKCS7Padding"},
                    { "AES", "AES/GCM/NoPadding"},

            };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_crypto_test);


        //
        // Generate public and private key pair
        //
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(Crypt.INTERNAL_ASYMMETRIC_ENCRYPTION_NAME);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        kpg.initialize(Crypt.RSA_KEY_SIZE);
        KeyPair kp = kpg.genKeyPair();

        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        String pass = "FooFeeFooBar";

        for (int i = 0; i < encSchemes.length; i++)
        {
            String en = encSchemes[i][0];
            String ea = encSchemes[i][1];
            try {
                appendLog("Trying enc: " + en + "," + ea);
                int ks = Crypt.calcMaxKeySize(en, ea);
                appendLog("keysize: " + ks);
                byte[] epk = encryptPrivateKey(en, ea, ks, privateKey, pass);
                decryptPrivateKey(en, ea, ks, pass, epk);
                appendLog("succcess");
            }
            catch (Exception e)
            {
                e.printStackTrace();
                appendLog(e.toString());
            }
        }

        ((TextView)findViewById(R.id.foo)).setText(log);
    }



    private static PrivateKey decryptPrivateKey(String en,String ea,int ks, String password, byte [] encryptedPrivateKey)
    {
        try {
            // Crypt keyDecryptor = new
            // Crypt(Crypt.getRawKeyOldWay(password.getBytes(), prefs.salt),
            // prefs.salt);
            Crypt keyDecryptor = new Crypt(Crypt.getRawKey(ks,password, salt),ea,ks);

            byte[] output = new byte[keyDecryptor
                    .getNumOutputBytesForDecryption(encryptedPrivateKey.length)];

            int keyLength = keyDecryptor.decryptData(output,
                    encryptedPrivateKey);

            byte[] output2 = new byte[keyLength];
            System.arraycopy(output, 0, output2, 0, keyLength);

            // Private keys are encoded with PKCS#8 (or so they say)
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(output);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            //we are assuming all errors are because of a wrong password


            //TODO 3: we could alternately store an additional digest of the password,
            //and check against that, but it seems that it would be another avenue of attack.
            //and not worth it
            appendLog("Password decryption exception: "+e);

            return null;
        }
    }

    private static void appendLog(String s) {
        log += s+"\n";
    }

    private static byte[] encryptPrivateKey(String en, String ea,int ks,PrivateKey privateKey, String password) {


        salt = new byte[SALT_LENGTH];

        /* ttt_installer:remove_line */
        Log.d(TAG, "Generating salt");
        //
        // Generate salt
        //
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(salt);

        /* ttt_installer:remove_line */Log.d(TAG, "Encrypting private key");
        //
        // Encrypt private key
        //

        Crypt keyEncryptor = new Crypt(Crypt.getRawKey(ks,password, salt),ea,ks);

        byte[] privateKeyData = privateKey.getEncoded();

        byte[] encryptedPrivateKey = new byte[keyEncryptor
                .getNumOutputBytesForEncryption(privateKeyData.length)];
        keyEncryptor.encryptData(encryptedPrivateKey, 0, privateKeyData,
                0, privateKeyData.length);

        return encryptedPrivateKey;
    }
}
