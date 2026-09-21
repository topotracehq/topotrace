plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.topotrace.agent"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.topotrace.agent"
        // minSdk 26 (Android 8.0) -- the oldest version WorkManager's
        // periodic scheduling and BatteryManager's isCharging() query
        // both behave consistently on, without extra API-level branching.
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = true
        buildConfig = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    // WorkManager -- periodic background reporting, survives process death
    // and reboot (re-scheduled automatically), the same "runs unattended
    // on an interval" role cron plays for the Linux/macOS agent and the
    // DaemonSet/CronJob play in the Helm chart.
    implementation("androidx.work:work-runtime-ktx:2.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
}
