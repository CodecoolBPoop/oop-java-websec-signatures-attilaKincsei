package main.java.com.codecool.websec;

import java.io.*;
import java.security.*;

class GenSig {

    public static void main(String[] args) {

        /* Generate a DSA signature */

        if (args.length != 1) {
            System.out.println("Usage: GenSig nameOfFileToSign");
        }
        else try {
            // 1.1. Create a Key Pair Generator
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");

            // 1.2. Initialize the key pair generator.
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(1024, random);

            // 1.3. generate the key pair and to store the keys in PrivateKey and PublicKey objects.
            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey priv = pair.getPrivate();
            PublicKey pub = pair.getPublic();

            // 2. Signing the data; generating a signature for data
            // 2.1.: Get a Signature Object:
            Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");

            // 2.2.: Initialize the Signature Object with the private key
            dsa.initSign(priv);

            // 2.3.: Supply the Signature Object the Data (from a file) to Be Signed
            FileInputStream fis = new FileInputStream(args[0]);
            BufferedInputStream bufin = new BufferedInputStream(fis);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = bufin.read(buffer)) >= 0) {
                dsa.update(buffer, 0, len);
            };
            bufin.close();

            // 2.4.: Generate the Signature:
            byte[] realSig = dsa.sign();

            // 3. Saving the signature in a file
            FileOutputStream sigfos = new FileOutputStream("sig");
            sigfos.write(realSig);
            sigfos.close();

            /* save the public key in a file */
            byte[] key = pub.getEncoded();
            FileOutputStream keyfos = new FileOutputStream("suepk");
            keyfos.write(key);
            keyfos.close();

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
}