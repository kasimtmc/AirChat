import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.plyg.airchat.core"
    compileSdk {
        version = release(37)
    }
    ndkVersion = libs.versions.ndk.get()

    defaultConfig {
        minSdk = 29
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    // UniFFI's Kotlin bindings call into the Rust library through JNA.
    implementation(libs.jna) {
        artifact { type = "aar" }
    }
}

/** Runs cargo inside the Rust workspace. */
abstract class CargoTask : DefaultTask() {
    @get:Inject
    abstract val exec: ExecOperations

    @get:Internal
    abstract val workspace: DirectoryProperty

    protected fun cargo(args: List<String>, env: Map<String, String> = emptyMap()) {
        // Android Studio does not always inherit the shell PATH, so prefer rustup's default location.
        val cargoHome = System.getenv("CARGO_HOME")?.let(::File)
            ?: File(System.getProperty("user.home"), ".cargo")
        val cargo = File(cargoHome, "bin/cargo").takeIf { it.canExecute() }?.path ?: "cargo"
        try {
            exec.exec {
                workingDir = workspace.get().asFile
                environment(env)
                commandLine(listOf(cargo) + args)
            }
        } catch (e: Exception) {
            throw GradleException(
                "cargo ${args.first()} failed. If Rust or cargo-ndk is missing, see README.md → Building.", e
            )
        }
    }
}

/** Cross-compiles the Rust core for each Android ABI with cargo-ndk. */
abstract class CargoNdkBuild : CargoTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val apiLevel: Property<Int>

    @get:Internal
    abstract val ndkDirectory: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun build() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        cargo(
            listOf("ndk", "--platform", apiLevel.get().toString()) +
                abis.get().flatMap { listOf("-t", it) } +
                listOf("-o", out.path, "build", "--release", "-p", "airchat-ffi"),
            env = mapOf("ANDROID_NDK_HOME" to ndkDirectory.get().asFile.path),
        )
    }
}

/** Generates the Kotlin bindings from the metadata embedded in a built airchat-ffi library. */
abstract class UniffiBindgen : CargoTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val library: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val config: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        cargo(
            listOf(
                "run", "-p", "uniffi-bindgen", "--",
                "generate", "--library", library.get().asFile.path,
                "--language", "kotlin", "--out-dir", out.path, "--no-format",
            )
        )
    }
}

val rustWorkspace: Directory = rootProject.layout.projectDirectory.dir("rust")
val rustSources = fileTree(rustWorkspace) { exclude("target/**") }
val androidAbis = providers.gradleProperty("airchat.abis").get().split(",")

androidComponents {
    onVariants { variant ->
        val suffix = variant.name.replaceFirstChar { it.uppercase() }
        val cargoBuild = tasks.register<CargoNdkBuild>("cargoNdkBuild$suffix") {
            workspace.set(rustWorkspace)
            sources.from(rustSources)
            abis.set(androidAbis)
            apiLevel.set(variant.minSdk.apiLevel)
            ndkDirectory.set(androidComponents.sdkComponents.ndkDirectory)
        }
        val bindgen = tasks.register<UniffiBindgen>("uniffiBindgen$suffix") {
            workspace.set(rustWorkspace)
            // Any ABI works: the metadata is identical, only the machine code differs.
            library.set(cargoBuild.flatMap { it.outputDir.file("arm64-v8a/libairchat_ffi.so") })
            config.set(rustWorkspace.file("airchat-ffi/uniffi.toml"))
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargoBuild, CargoNdkBuild::outputDir)
        variant.sources.kotlin?.addGeneratedSourceDirectory(bindgen, UniffiBindgen::outputDir)
    }
}
