package org.example.pbe;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class PbeBootstrap {
    
    // The fully qualified name of your main PBE utility class
    private static final String MAIN_CLASS = "org.example.pbe.PasswordBasedEncryptionUtil`";
    
    // Directory where embedded JARs are located (could be configurable)
    private static final String JARS_DIR = "lib";
    
    public static void main(String[] args) {
        try {
            // Find all JARs to be loaded
            List<URL> jarUrls = findJars();
            
            if (jarUrls.isEmpty()) {
                System.err.println("No JAR files found in: " + JARS_DIR);
                System.exit(1);
            }
            
            // Create our custom classloader with the JAR URLs
            ClassLoader parentClassLoader = PbeBootstrap.class.getClassLoader();
            EmbeddedJarsClassLoader classLoader = new EmbeddedJarsClassLoader(
                    jarUrls.toArray(new URL[0]), 
                    parentClassLoader
            );
            
            // Load the main class using our custom classloader
            Class<?> mainClass = classLoader.loadClass(MAIN_CLASS);
            
            // Get the main method
            Method mainMethod = mainClass.getMethod("main", String[].class);
            
            // Call the main method passing the command line arguments
            mainMethod.invoke(null, (Object) args);
            
        } catch (Exception e) {
            System.err.println("Error bootstrapping PBE utility: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private static List<URL> findJars() throws Exception {
        List<URL> jarUrls = new ArrayList<>();
        
        File jarsDir = new File(JARS_DIR);
        if (!jarsDir.exists() || !jarsDir.isDirectory()) {
            // Try to find the directory relative to the JAR location
            URL location = PbeBootstrap.class.getProtectionDomain().getCodeSource().getLocation();
            jarsDir = new File(new File(location.toURI()).getParentFile(), JARS_DIR);
        }
        
        if (jarsDir.exists() && jarsDir.isDirectory()) {
            File[] jarFiles = jarsDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".jar"));
            if (jarFiles != null) {
                for (File jarFile : jarFiles) {
                    jarUrls.add(jarFile.toURI().toURL());
                }
            }
        }
        
        return jarUrls;
    }
}