package org.example.pbe;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

public class EmbeddedJarsClassLoader extends URLClassLoader {

    public EmbeddedJarsClassLoader(URL[] urls, ClassLoader parent) {
        super(urls, parent);
    }

    /**
     * Functional interface to handle jar operations
     */
    @FunctionalInterface
    private interface JarEntryProcessor<T> {
        T process(URL url, JarFile jarFile, JarEntry jarEntry) throws IOException;
    }

    /**
     * Generic method to process jar entries
     */
    private <T> T processJarEntry(URL url, String entryName, JarEntryProcessor<T> processor) {
        try (JarFile jarFile = new JarFile(new File(url.getFile()))) {
            JarEntry jarEntry = jarFile.getJarEntry(entryName);
            if (jarEntry != null) {
                return processor.process(url, jarFile, jarEntry);
            }
        } catch (IOException ex) {
            System.err.println("Error processing JAR: " + url + " - " + ex.getMessage());
        }
        return null;
    }

    /**
     * Process all jars for a given entry name
     */
    private <T> List<T> processAllJars(String entryName, JarEntryProcessor<T> processor) {
        return Arrays.stream(getURLs())
                .map(url -> processJarEntry(url, entryName, processor))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /**
     * Process jars until a non-null result is found
     */
    private <T> T processJarsUntilResult(String entryName, JarEntryProcessor<T> processor) {
        return Arrays.stream(getURLs())
                .map(url -> processJarEntry(url, entryName, processor))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        try {
            // First, check if the class is already loaded by the parent classloader
            return super.findClass(name);
        } catch (ClassNotFoundException ignored) {
            // Ignore and continue to load from embedded JARs
        }

        // Class not found in parent, try to load from embedded JARs
        String entryName = name.replace('.', '/') + ".class";

        Class<?> result = processJarsUntilResult(entryName, (url, jarFile, jarEntry) -> {
            try (InputStream inputStream = jarFile.getInputStream(jarEntry)) {
                byte[] classBytes = readAllBytes(inputStream);
                ProtectionDomain protectionDomain = getClass().getProtectionDomain();
                return defineClass(name, classBytes, 0, classBytes.length, protectionDomain);
            }
        });

        if (result != null) {
            return result;
        }

        // Class not found in any embedded JAR
        throw new ClassNotFoundException("Class not found in embedded JARs: " + name);
    }

    @Override
    public URL findResource(String name) {
        return processJarsUntilResult(name, (url, jarFile, jarEntry) -> {
            try {
                return new URL("jar:" + url + "!/" + name);
            } catch (IOException ex) {
                System.err.println("Error creating URL for resource: " + name + " - " + ex.getMessage());
                return null;
            }
        });
    }

    @Override
    public Enumeration<URL> findResources(String name) {
        List<URL> resources = processAllJars(name, (url, jarFile, jarEntry) -> {
            try {
                return new URL("jar:" + url + "!/" + name);
            } catch (IOException ex) {
                System.err.println("Error creating URL for resource: " + name + " - " + ex.getMessage());
                return null;
            }
        });

        return Collections.enumeration(resources);
    }

    // Utility method for reading all bytes from an InputStream (Java 8 compatible)
    private static byte[] readAllBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[16384]; // Use a reasonable buffer size
        while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }
}