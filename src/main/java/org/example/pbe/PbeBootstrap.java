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

        // Try logging like this to get more insight where it is failing?
        try {
            System.out.println("Before attempting to access the class");
            System.out.println("Current thread classloader: " + Thread.currentThread().getContextClassLoader());
            
            // Instead of directly calling the static method, let's break this down:
            String className = "com.example.ProblemClass"; // Replace with actual class name
            System.out.println("Attempting to load class: " + className);
            
            // Try to load the class explicitly using our classloader
            Class<?> problemClass = Thread.currentThread().getContextClassLoader().loadClass(className);
            System.out.println("Successfully loaded class: " + className);
            System.out.println("Class's classloader: " + problemClass.getClassLoader());
            
            // Now try to access the method
            String methodName = "problematicMethod"; // Replace with actual method name
            System.out.println("Attempting to get method: " + methodName);
            Method method = problemClass.getMethod(methodName, /* parameter types */);
            System.out.println("Successfully got method: " + methodName);
            
            // Now try to invoke it
            System.out.println("Attempting to invoke method");
            Object result = method.invoke(null /* since it's static */);
            System.out.println("Successfully invoked method");
        } catch (Throwable t) {
            System.err.println("Exception type: " + t.getClass().getName());
            System.err.println("Exception message: " + t.getMessage());
            t.printStackTrace();
            
            // If it's an InvocationTargetException, get the cause
            if (t instanceof InvocationTargetException) {
                Throwable cause = ((InvocationTargetException) t).getTargetException();
                System.err.println("Invocation cause type: " + cause.getClass().getName());
                System.err.println("Invocation cause message: " + cause.getMessage());
                cause.printStackTrace();
            }
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