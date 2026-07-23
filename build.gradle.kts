plugins {
    id("java")
    application
}

group = "ru.merkii"
version = "1.0-SNAPSHOT"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

application {
    mainClass.set("ru.merkii.crypt.Main")
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:6.0.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    implementation("org.ow2.asm:asm:9.8")
    implementation("org.ow2.asm:asm-tree:9.8")
}

tasks.test {
    useJUnitPlatform()
}

// The reversal agent ships as its own small, ASM-free jar - it's meant to sit
// next to a protected app and be attached with -javaagent, not to be part of
// this tool's own CLI jar.
val agentJar by tasks.registering(Jar::class) {
    archiveClassifier.set("agent")
    from(sourceSets.main.get().output) {
        include("ru/merkii/crypt/agent/**")
        include("ru/merkii/crypt/OpcodeTable*.class")
    }
    manifest {
        attributes("Premain-Class" to "ru.merkii.crypt.agent.OpcodeRestoringAgent")
    }
}

tasks.build {
    dependsOn(agentJar)
}