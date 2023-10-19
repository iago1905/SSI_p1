import java.io.*;

import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Empaquetar{
    public static void main(String[] args) throws Exception {
        //Generar secretKey
        SecretKey claveSecreta = generaSecretKey();

        //Cifrar examen
        byte[] examenCifrado = cifrarExamen(claveSecreta, "examen.txt");
        System.out.println("Examen cifrado: " + examenCifrado);
        System.out.println(bytesToHex(examenCifrado));

        //Cifrar claveSecreta con clave pública del profesor
        byte[] claveCifrada = cifrarClave(claveSecreta);
        System.out.println("Clave cifrada: " + claveCifrada);
        System.out.println(bytesToHex(claveCifrada));

        //Hash de la claveSecreta cifrada
        byte[] hashClaveSecretaExamenCifrado = hashClaveSecretaCifrada(claveCifrada, examenCifrado);
        System.out.println("Hash: " + hashClaveSecretaExamenCifrado);
        System.out.println(bytesToHex(hashClaveSecretaExamenCifrado));

        //Cifrar hash clave publica alumno
        byte[] hashCifrado = cifrarHashClavePrivadaAlumno(hashClaveSecretaExamenCifrado);
        System.out.println("Hash cifrado: " + hashCifrado);
        System.out.println(bytesToHex(hashCifrado));

        //Empaquetar
        Paquete paquete = new Paquete();

        paquete.anadirBloque("examenCifrado", examenCifrado);
        paquete.anadirBloque("claveCifrada", claveCifrada);
        paquete.anadirBloque("hashCifrado", hashCifrado);

        paquete.escribirPaquete("paquete.bin");
    }

    //SecretKey para cifrar el examen

    public static SecretKey generaSecretKey() throws Exception{
        //Crear clave simétrica
        KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
        generadorDES.init(56);
        SecretKey claveSecreta = generadorDES.generateKey();

        return claveSecreta;

    }

    public static byte[] cifrarExamen(SecretKey claveSecreta, String inputFile) throws Exception{
        //Cifrar examen con clave simétrica. Inicializar cifrador
        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cifrador.init(Cipher.ENCRYPT_MODE, claveSecreta);
        //Cargar archivo de entrada y preparar el de salida
        FileInputStream in = new FileInputStream(inputFile);
        CipherInputStream cifradoIn = new CipherInputStream(in, cifrador);
        //Cifrar archivo
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesLeidos;
        while((bytesLeidos = cifradoIn.read(buffer)) != -1) {
            //devolver byte[] cifrado
            byteArrayOutputStream.write(buffer, 0, bytesLeidos);
        }

        in.close();
        cifradoIn.close();
        // Devolver byte[] cifrado
        return byteArrayOutputStream.toByteArray();
    }

    public static byte[] cifrarClave(SecretKey claveSecreta) throws Exception{
      
         //Cifrar clave simétrica con la clave pública del profesor
        FileInputStream in = new FileInputStream("profesor.publica");

        byte[] encodedPKCS8 = new byte[in.available()];
        in.read(encodedPKCS8);
        in.close();
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publiKeySpec = new X509EncodedKeySpec(encodedPKCS8);  // clave publica del profesor
        //PKCS8EncodedKeySpec publicKeySpec = new PKCS8EncodedKeySpec(encodedPKCS8);  // clave publica del profesor
        PublicKey clavePublicaProfesor = keyFactoryRSA.generatePublic(publiKeySpec);
        Cipher cifrar = Cipher.getInstance("RSA/ECB/PKCS1Padding");//, "BC");
        cifrar.init(Cipher.ENCRYPT_MODE, clavePublicaProfesor);
        byte[] clave = claveSecreta.getEncoded();
        
        System.out.println("Clave getencoded: " + bytesToHex(clave)); //3d8a689d34aece1a
        //cifrar.update(clave);
        byte[] fin = cifrar.doFinal(clave);
        return fin;//clave secreta cifrada con clave pública del profesor, para incluir en el paquete
        
    }
    

    public static byte[] hashClaveSecretaCifrada(byte[] claveCifrada, byte[] examenCifrado) throws Exception{ //parametro a pasar???
        //Calcular hash del examen
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(examenCifrado);
        hash.update(claveCifrada);
        byte[] hashClaveCifradaExamenCirfrado = hash.digest();
        

        return hashClaveCifradaExamenCirfrado;
    }

    public static byte[] cifrarHashClavePrivadaAlumno(byte[] hashClaveCifradaExamenCirfrado) throws Exception{
        FileInputStream in = new FileInputStream("alumno.privada");

        byte[] encodedPKCS8 = new byte[in.available()];
        in.read(encodedPKCS8);
        in.close();
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPKCS8);  // clave publica del profesor
        PrivateKey clavePrivadaAlumno = keyFactoryRSA.generatePrivate(privateKeySpec);
        
        Cipher cifrar = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cifrar.init(Cipher.ENCRYPT_MODE, clavePrivadaAlumno);
        byte[] hash = hashClaveCifradaExamenCirfrado; //puede sobrar esta linea
        //cifrar.update(hash);
        byte[] fin = cifrar.doFinal(hash);
        return fin;
    }
    



    //curiosidad
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
}
