import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Date;


public class Ejercicio {
    public static void main(String[] args) throws Exception {
        // Generar claves profesor / alumno / sellado
        System.out.println("Generando claves...");
        GenerarClaves.main(new String[] { "profesor" });
        GenerarClaves.main(new String[] { "alumno" });
        GenerarClaves.main(new String[] { "sellado" });
        System.out.println("claves generadas...");

        // empaquetar examen.txt ((archivo examen.txt creado a mano))
        System.out.println("\nEmpaquetando examen...");
        Empaquetar.main();
        System.out.println("examen empaquetado...");

        // Añadir al paquete 'sello' y 'fechaSellado'
        //El paquete de sello añadae la fecha de sellado
        System.out.println("\nAñadiendo sello y fecha de sellado...");
        SellarExamen.main(new String[] { "paquete.bin" });
        //System.out.println("sello y fecha de sellado añadidos..."); AÑADIDO en sellarexamen.java

        // esempaquetarExamen paquete.bin ((el sellado donde se guarda? el return de
        // cifrarSellado es un byte[] que no almacenamos en ningun sitio))
        System.out.println("\nDesempaquetando examen...");
        Desempaquetar.main(new String[] { "paquete.bin" });
        System.out.println("examen desempaquetado...");

    }

}
