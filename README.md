# wcrypt - Simple Java library for easy cryptography
[![Gradle Publish](https://github.com/LCLPYT/wcrypt/actions/workflows/gradle-publish.yml/badge.svg)](https://github.com/LCLPYT/wcrypt/actions/workflows/gradle-publish.yml)

## Installation
To use wcrypt in your project, modify your `project.gradle`:
```groovy
repositories {
    mavenCentral()
    
    maven {
        url "https://repo.lclpnet.work/repository/internal"
    }
}

dependencies {
    implementation 'work.lclpnet:wcrypt:1.0.0'  // replace with your version
}
```
All available versions can be found [here](https://repo.lclpnet.work/#artifact/work.lclpnet/wcrypt).

## Credits
- [Java AES Encryption and Decryption](https://www.baeldung.com/java-aes-encryption-decryption) - Baeldung.com; on 
[GitHub](https://github.com/eugenp/tutorials/tree/62a74a6b2827ab0760b98ba173ebff2f3c884d01/core-java-modules/core-java-security-algorithms)