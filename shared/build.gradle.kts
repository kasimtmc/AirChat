plugins {
    alias(libs.plugins.android.library)
}

/** What the AirChat app and the provider app share: the transports and Air Provider mode. */
android {
    namespace = "com.plyg.airchat.shared"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        minSdk = 29
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        buildConfig = true
    }
}

dependencies {
    api(project(":core-bridge"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.android)
}
