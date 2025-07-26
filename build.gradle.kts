import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.*

plugins {
    id("idea")

    id("maven-publish")
    id("com.gradleup.shadow") version "8.3.0"

    kotlin("jvm") version "2.0.0"
}

group = "net.cakemc"
version = "1.0-SNAPSHOT"

val repoProperties = Properties()
val repoFile = file("/credentials.properties")
if (repoFile.exists())
    repoProperties.load(repoFile.inputStream())
val repoUsername: String = (repoProperties["username"] ?: System.getenv("REPOSITORY_USERNAME")).toString()
val repoPassword: String = (repoProperties["password"] ?: System.getenv("REPOSITORY_PASSWORD")).toString()

repositories {
    mavenLocal()
    mavenCentral()
    maven {
        name = "cakemc-nexus"
        url = URI.create("http://cakemc.net:8080/releases")
        credentials {
            username = repoUsername
            password = repoPassword
        }
        isAllowInsecureProtocol = true
    }
}

publishing {
    publications.create<MavenPublication>(rootProject.name) {
        artifact(tasks.shadowJar)
    }
    repositories {
        maven {
            name = "cakemc"
            url = URI.create("http://cakemc.net:8080/releases")
            credentials {
                username = repoUsername
                password = repoPassword
            }
            isAllowInsecureProtocol = true
        }
    }
}

@Suppress("unchecked_cast")
fun <V> prop(value: String): V {
    return properties.getValue(value) as V
}

dependencies {

    implementation(
        group = "io.netty",
        name = "netty-common",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-common",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-buffer",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-buffer",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-codec",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-codec",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-codec-dns",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-codec-dns",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-resolver",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-resolver",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-resolver-dns",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-resolver-dns",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-resolver-dns-classes-macos",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-resolver-dns-classes-macos",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-resolver-dns-native-macos",
        version = prop("dep-netty"),
        classifier = "osx-aarch_64"
    )
    shadow(
        group = "io.netty",
        name = "netty-resolver-dns-native-macos",
        version = prop("dep-netty"),
        classifier = "osx-aarch_64"
    )

    implementation(
        group = "io.netty",
        name = "netty-resolver-dns-native-macos",
        version = prop("dep-netty"),
        classifier = "osx-x86_64"
    )
    shadow(
        group = "io.netty",
        name = "netty-resolver-dns-native-macos",
        version = prop("dep-netty"),
        classifier = "osx-x86_64"
    )

    implementation(
        group = "io.netty",
        name = "netty-codec",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-codec",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-transport",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-transport",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-transport-classes-epoll",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-transport-classes-epoll",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-transport-classes-kqueue",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-transport-classes-kqueue",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-transport-native-epoll",
        version = prop("dep-netty"),
        classifier = "linux-aarch_64"
    )
    shadow(
        group = "io.netty",
        name = "netty-transport-native-epoll",
        version = prop("dep-netty"),
        classifier = "linux-aarch_64"
    )

    implementation(
        group = "io.netty",
        name = "netty-transport-native-epoll",
        version = prop("dep-netty"),
        classifier = "linux-riscv64"
    )
    shadow(
        group = "io.netty",
        name = "netty-transport-native-epoll",
        version = prop("dep-netty"),
        classifier = "linux-riscv64"
    )

    implementation(
        group = "io.netty",
        name = "netty-transport-native-epoll",
        version = prop("dep-netty"),
        classifier = "linux-x86_64"
    )
    shadow(
        group = "io.netty",
        name = "netty-transport-native-epoll",
        version = prop("dep-netty"),
        classifier = "linux-x86_64"
    )

    implementation(
        group = "io.netty",
        name = "netty-transport-native-kqueue",
        version = prop("dep-netty"),
        classifier = "osx-aarch_64"
    )
    shadow(
        group = "io.netty",
        name = "netty-transport-native-kqueue",
        version = prop("dep-netty"),
        classifier = "osx-aarch_64"
    )

    implementation(
        group = "io.netty",
        name = "netty-transport-native-kqueue",
        version = prop("dep-netty"),
        classifier = "osx-x86_64"
    )
    shadow(
        group = "io.netty",
        name = "netty-transport-native-kqueue",
        version = prop("dep-netty"),
        classifier = "osx-x86_64"
    )

    implementation(
        group = "io.netty",
        name = "netty-codec-http",
        version = prop("dep-netty"),
    )
    shadow(
        group = "io.netty",
        name = "netty-codec-http",
        version = prop("dep-netty"),
    )

    implementation(
        group = "io.netty",
        name = "netty-transport-native-unix-common",
        version = prop("dep-netty"),
    )
    shadow(
        group = "io.netty",
        name = "netty-transport-native-unix-common",
        version = prop("dep-netty"),
    )

    implementation(
        group = "io.netty",
        name = "netty-handler",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-handler",
        version = prop("dep-netty")
    )

    implementation(
        group = "io.netty",
        name = "netty-handler-proxy",
        version = prop("dep-netty")
    )
    shadow(
        group = "io.netty",
        name = "netty-handler-proxy",
        version = prop("dep-netty")
    )
}

val jdkVersion = JavaVersion.VERSION_21
val jdkVersionString = jdkVersion.toString()

java {
    toolchain.languageVersion = JavaLanguageVersion.of(jdkVersionString)
    withSourcesJar()
}

tasks.withType<JavaCompile> {
    options.encoding = StandardCharsets.UTF_8.toString()
}

tasks.withType<Jar> {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })
}

tasks.withType<AbstractArchiveTask> {
    isReproducibleFileOrder = true
    isPreserveFileTimestamps = false
}

kotlin {
    jvmToolchain(21)
}
