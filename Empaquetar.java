import java.io.*;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Empaquetar{
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
        
        //Cargar clave privada del alumno
        File ficheroClavePrivada = new File("alumno.privada"); 
		int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
		byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
		FileInputStream in = new FileInputStream(ficheroClavePrivada);
		in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
		in.close();

		// 2.2 Recuperar clave privada desde datos codificados en formato PKCS8
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
		PrivateKey clavePrivada2 = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
    
        //Crear cifrador que empaquete el examen con clave privada del profesor
        Cipher cifrador = Cipher.getInstance("DES", "BC");
        cifrador.init(Cipher.ENCRYPT_MODE, clavePrivada2);
    
        //Cargar examen.pdf
        in = new FileInputStream("examen.pdf");
        byte[] examen = new byte[in.available()];
        in.read(examen);
        in.close();
    
        //Cifrar examen
        cifrador.update(examen);
        
        //Escribir examen cifrado en archivo
        FileOutputStream out = new FileOutputStream("examen.cifrado");
        out.write(cifrador.doFinal());
        out.close();    
        
       

/*
        //Cargar examen.pdf
        in = new FileInputStream("examen.pdf");
        byte[] examen = new byte[in.available()];
        in.read(examen);
        in.close();
        
        //Firmar examen
        firma.update(examen);
        byte[] firmaExamen = firma.sign();

        //Empaquetar examen y firma
        Paquete paquete = new Paquete();
        paquete.anadirBloque("firma", firmaExamen); //examen cifrado clave privada del alumno

        //Volcar paquete a fichero
        paquete.escribirPaquete("examen.paquete");


 */
        
    }

    public static void cifrarExamen() throws Exception{                                                 
        

    }

    public static SecretKey generaSecretKey() throws Exception{
        //Crear clave simétrica
        KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
        generadorDES.init(56);
        SecretKey claveSecreta = generadorDES.generateKey();

        return claveSecreta;

    }

    public static byte[] cifrarClave(SecretKey claveSecreta) throws Exception{
        //Cifrar clave simétrica con la clave pública del profesor
        FileInputStream in = new FileInputStream("profesor.publica");

        byte[] encodedPKCS8 = new byte[in.available()];
        in.read(encodedPKCS8);
        in.close();
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
        PKCS8EncodedKeySpec publicKeySpec = new PKCS8EncodedKeySpec(encodedPKCS8);
        PublicKey clavePublicaProfesor = keyFactoryRSA.generatePublic(publicKeySpec);

        Cipher cifrar = Cipher.getInstance("RSA", "BC");
        cifrar.init(Cipher.ENCRYPT_MODE, clavePublicaProfesor);
        byte[] clave = claveSecreta.getEncoded();
        byte[] claveCifrada = cifrar.update(clave);
        
        return claveCifrada;
    }

    
}