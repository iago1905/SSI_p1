import java.io.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Date;

import java.security.*;

import java.security.spec.*;

import javax.crypto.*;

public class SellarExamen{
    public static void main(String[] args) throws Exception {
    // TODO code application logic here
    if (args[0] != "paquete.bin" && args.length != 1) {
            System.err.println("Número de argumentos incorrecto.");
            System.err.println("Uso: java SellarExamen <nombre_paquete>");
            System.exit(1);
        }

        Paquete paquete = new Paquete(args[0]);
        byte[] examenCifrado = paquete.getContenidoBloque("examenCifrado");
        byte[] claveCifrada = paquete.getContenidoBloque("claveCifrada");
        byte[] hashCifrado = paquete.getContenidoBloque("hashCifrado");

        if (verificarHash(descifrarHashClavePrivadaAlumno(hashCifrado), hashClaveSecretaCifrada(claveCifrada, examenCifrado))){
            System.out.println("El hash es correcto, se sellará el examen");
            sellar(hashSellado(claveCifrada, examenCifrado, hashCifrado),paquete);
            añadriFechaSellado(paquete);

            paquete.escribirPaquete("paquete.bin");
        }else{
            System.out.println("El hash no es correcto, los datos fueron modificados");
        }
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
    }

    public static byte[] hashSellado(byte[] claveCifrada, byte[] examenCifrado, byte[] hashCifrado) throws Exception{ //parametro a pasar???
        //Calcular hash del examen
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(examenCifrado);
        hash.update(claveCifrada);
        hash.update(hashCifrado);
        byte[] hashSellado = hash.digest();


        return hashSellado;
    }

    public static void sellar(byte[] hashSellado, Paquete paquete) throws Exception{
        FileInputStream in = new FileInputStream("sellado.privada");

        byte[] encodedPKCS8 = new byte[in.available()];
        in.read(encodedPKCS8);
        in.close();
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPKCS8);  
        PrivateKey clavePrivadaAlumno = keyFactoryRSA.generatePrivate(privateKeySpec);

        Cipher cifrar = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cifrar.init(Cipher.ENCRYPT_MODE, clavePrivadaAlumno);
        //byte[] hash = hashSellado; //puede sobrar esta linea
        //cifrar.update(hash);
        byte[] fin = cifrar.doFinal(hashSellado);

        paquete.anadirBloque("sello", fin);

    }
    private static void añadriFechaSellado(Paquete paquete) {
         ///añadir fecha, porcion codigo extraido de SellarExamen.java
        Date fecha = new Date();
        long fechaLong = fecha.getTime(); //convertir fecha a long
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES); //crear buffer de bytes
        buffer.putLong(fechaLong); //escribir long en el buffer
        byte[] fechaBytes = buffer.array(); //obtener bytes del buffer
        System.out.println("Fecha en bytes: " + fechaBytes);
        paquete.anadirBloque("fechaSellado", fechaBytes);

        System.out.println("Fecha añadida al paquete");
    }
}
