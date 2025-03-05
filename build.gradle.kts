plugins {
    java
    id("io.freefair.lombok") version "8.12.2"
}

group = "org.example"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jasypt:jasypt:1.9.3")
    implementation("org.bouncycastle:bc-fips:2.1.0")

    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}