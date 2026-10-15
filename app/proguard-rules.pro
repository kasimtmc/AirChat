# R8 for release builds (app/build.gradle.kts: optimization).
#
# No renaming. AirChat is open source, so obfuscation hides nothing, and renaming let R8 move a part
# of a Kotlin multi-file class (CollectionsKt__MutableCollectionsJVMKt) into another package than
# its package-private superclass: the app crashed at start with IllegalAccessError. Shrinking and
# optimizing go on; stack traces stay readable.
-dontobfuscate
