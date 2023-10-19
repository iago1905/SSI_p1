import java.io.*;

import java.util.Arrays;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Desempaquetar {
    public static void main(String[] args) throws Exception {
    // TODO code application logic here
    desempaquetar("paquete.bin");
    }



    public static void desempaquetar(String nombreFichero) throws Exception {
        Paquete paquete = new Paquete();
        paquete.leerPaquete(nombreFichero);

        byte[] examenCifrado = paquete.getContenidoBloque("examenCifrado");
        byte[] claveCifrada = paquete.getContenidoBloque("claveCifrada");
        byte[] hashCifrado = paquete.getContenidoBloque("hashCifrado");


        //Descifrar clave
        byte[] claveDescifrada = descifrarClave(claveCifrada);
        System.out.println("Clave descifrada: " + claveDescifrada);
        System.out.println(bytesToHex(claveDescifrada));

        //Descifrar examen
        byte[] examenDescifrado = descifrarExamen(claveDescifrada, examenCifrado);
        System.out.println("Examen descifrado: " + examenDescifrado);
        System.out.println(bytesToHex(examenDescifrado));

        //Hash de la claveSecreta cifrada
        byte[] hashClaveSecretaExamenCifrado = hashClaveSecretaCifrada(claveCifrada, examenCifrado);
        System.out.println("Hash: " + hashClaveSecretaExamenCifrado);
        System.out.println(bytesToHex(hashClaveSecretaExamenCifrado));

        //Descifrar hash
        byte[] hashDescifrado = descifrarHashClavePrivadaAlumno(hashCifrado);
        System.out.println("Hash descifrado: " + hashDescifrado);
        System.out.println(bytesToHex(hashDescifrado));

        //Verificar hash
        if(verificarHash(hashDescifrado,hashClaveSecretaExamenCifrado)){
            System.out.println("El hash es correcto");
            FileOutputStream out = new FileOutputStream("archivo.txt");
            out.write(examenDescifrado);
            out.flush();
            out.close();
        } else {
            System.out.println("El hash no es correcto");
        };
        
    }
    


    public static byte[] descifrarClave(byte[] claveCifrada) throws Exception{
        // Cargar clave privada del profesor desde el archivo "profesor.privada"
        FileInputStream privateKeyFile = new FileInputStream("profesor.privada");
        byte[] privateKeyBytes = new byte[privateKeyFile.available()];
        privateKeyFile.read(privateKeyBytes);
        privateKeyFile.close();

        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey clavePrivadaProfesor = keyFactoryRSA.generatePrivate(privateKeySpec);

        // Descifrar clave
        Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cifrador.init(Cipher.DECRYPT_MODE, clavePrivadaProfesor);
        byte[] datosDescifrados = cifrador.doFinal(claveCifrada);
        
        return datosDescifrados;
    }
    
    public static byte[] descifrarExamen(byte[] claveDescifrada, byte[] examenCifrado) throws Exception{
        //Generar clave secreta
        SecretKey claveDescifradaKey = new SecretKeySpec(claveDescifrada, 0, claveDescifrada.length, "DES");
        
        //Descifrar examen
        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cifrador.init(Cipher.DECRYPT_MODE, claveDescifradaKey);
        byte[] examenDescifrado = cifrador.doFinal(examenCifrado);
        
        return examenDescifrado;
    }

    public static byte[] descifrarHashClavePrivadaAlumno(byte[] hashCifrado ) throws Exception{
        // Cargar clave privada del alumno desde el archivo "alumno.privada"
        FileInputStream publicKeyFile = new FileInputStream("alumno.publica");
        byte[] publicKeyBytes = new byte[publicKeyFile.available()];
        publicKeyFile.read(publicKeyBytes);
        publicKeyFile.close();

        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey clavePublicaAlumno = keyFactoryRSA.generatePublic(publicKeySpec);

        // Descifrar hash
        Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cifrador.init(Cipher.DECRYPT_MODE, clavePublicaAlumno);
        byte[] datosDescifrados = cifrador.doFinal(hashCifrado);
        
        return datosDescifrados;
        //a7bf3bb4490bfbf0ab46a8b517ba8059cf867e3f87c0a747f0e697b3e4b4e0fd
    }


    public static byte[] hashClaveSecretaCifrada(byte[] claveCifrada, byte[] examenCifrado) throws Exception{ //parametro a pasar???
        //Calcular hash del examen
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(examenCifrado);
        hash.update(claveCifrada);
        byte[] hashClaveCifradaExamenCirfrado = hash.digest();
        

        return hashClaveCifradaExamenCirfrado;
    }

    public static boolean verificarHash(byte[] hashDescifrado, byte[] hashClaveSecretaExamenCifrado) throws Exception{
        return Arrays.equals(hashDescifrado, hashClaveSecretaExamenCifrado);
        /*FileInputStream publicKeyFile = new FileInputStream("alumno.publica");
        byte[] publicKeyBytes = new byte[publicKeyFile.available()];
        publicKeyFile.read(publicKeyBytes);
        publicKeyFile.close();

        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey clavePublicaAlumno = keyFactoryRSA.generatePublic(publicKeySpec);

        Signature verificado = Signature.getInstance("SHA256withRSA");
        verificado.initVerify(clavePublicaAlumno);
        verificado.update(hashClaveSecretaExamenCifrado);
        if(verificado.verify(hashDescifrado, 0, 32)){
            return true;
        }else{
            return false;
        }*/
    }




    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    
}


