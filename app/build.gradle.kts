import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

/**
 * The release key, from `keystore.properties` next to this project's settings (never committed):
 * `storeFile` and `keyAlias`, and the passwords there as `storePassword` and `keyPassword` or in the
 * environment as AIRCHAT_STORE_PASSWORD and AIRCHAT_KEY_PASSWORD. Without the file, release
 * builds are left unsigned.
 */
val releaseKey: Properties? = rootProject.file("keystore.properties").takeIf { it.isFile }?.let { file ->
    Properties().apply { file.inputStream().use(::load) }
}

android {
    namespace = "com.plyg.airchat"
    compileSdk {
        version = release(37)
    }
    // Needed to strip the native libraries (Rust core, JNA) when packaging.
    ndkVersion = libs.versions.ndk.get()

    defaultConfig {
        applicationId = "com.plyg.airchat"
        minSdk = 29
        targetSdk = 37
        versionCode = 2
        versionName = "0.2.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += providers.gradleProperty("airchat.abis").get().split(",")
        }
    }

    signingConfigs {
        if (releaseKey != null) {
            create("release") {
                storeFile = rootProject.file(releaseKey.getProperty("storeFile"))
                keyAlias = releaseKey.getProperty("keyAlias")
                storePassword = releaseKey.getProperty("storePassword") ?: System.getenv("AIRCHAT_STORE_PASSWORD")
                keyPassword = releaseKey.getProperty("keyPassword") ?: System.getenv("AIRCHAT_KEY_PASSWORD")
                // v3 so the key can be rotated later without users reinstalling. Every Android
                // this app runs on (10+) checks v3, so the signer leaves the v2 block out.
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }
    buildTypes {
        release {
            if (releaseKey != null) signingConfig = signingConfigs.getByName("release")
            optimization {
                enable = true
                packageScope = setOf("androidx.**", "kotlin.**", "kotlinx.**")
                keepRules { files.add(file("proguard-rules.pro")) }
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        buildConfig = true
        compose = true
    }
}

dependencies {
    implementation(project(":core-bridge"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment.ktx)
    // QR codes: drawn and read on the device, without Google Play services.
    implementation(libs.zxing.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}