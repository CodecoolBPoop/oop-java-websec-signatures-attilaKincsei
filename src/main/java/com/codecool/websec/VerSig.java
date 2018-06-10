package main.java.com.codecool.websec;

import java.io.*;
import java.security.*;
import java.security.spec.*;

class VerSig {

    public static void main(String[] args) {

        /* Verify a DSA signature */

        if (args.length != 3) {
            System.out.println("Usage: VerSig " +
                    "publickeyfile signaturefile " + "datafile");
        }
        else try {

            // 1.1. Input and Convert the Encoded Public Key Bytes
            FileInputStream keyfis = new FileInputStream(args[0]);
            byte[] encKey = new byte[keyfis.available()];
            keyfis.read(encKey);
            keyfis.close();

            // 1.2. Specify key
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);

            // 1.3. Convert data object with DSA keys.
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

            // 1.4. Generate a PublicKey from the key specification.
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            // 2. input the signature bytes from the file specified as the second command line argument.
            FileInputStream sigfis = new FileInputStream(args[1]);
            byte[] sigToVerify = new byte[sigfis.available()];
            sigfis.read(sigToVerify);
            sigfis.close();

            // 3. Verification:
            // 3.1. Instantiate the Signature Object for Verification
            Signature sig = Signature.getInstance("SHA1withDSA", "SUN");

            // 3.2. The initialization method for verification requires the public key:
            sig.initVerify(pubKey);

            // 3.2. Supply the Signature Object With the Data to be Verified
            FileInputStream datafis = new FileInputStream(args[2]);
            BufferedInputStream bufin = new BufferedInputStream(datafis);

            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                sig.update(buffer, 0, len);
            };

            bufin.close();

            // 4. Verify the Signature
            boolean verifies = sig.verify(sigToVerify);
            System.out.println("signature verifies: " + verifies);

            // Compile and run
            // javac -Xlint:all main/java/com/codecool/websec/VerSig.java
            // java main.java.com.codecool.websec.VerSig suepk sig input.txt
            // should print "signature verifies: true",if verification is successful

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }

}