plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

/**
 * The provider app (requirements AP-8): a spare phone with Wi-Fi Aware as an always-on Air
 * Provider. The same core and transports as AirChat, none of its account, contacts or screens.
 */
android {
    namespace = "com.plyg.airchat.provider"
    compileSdk {
        version = release(37)
    }
    // Needed to strip the native libraries (Rust core, JNA) when packaging.
    ndkVersion = libs.versions.ndk.get()

    defaultConfig {
        applicationId = "com.plyg.airchat.provider"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += providers.gradleProperty("airchat.abis").get().split(",")
        }
    }
    buildTypes {
        release {
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
    implementation(project(":shared"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.kotlinx.coroutines.android)
}
