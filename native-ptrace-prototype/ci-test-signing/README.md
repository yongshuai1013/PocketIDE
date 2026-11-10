# Public CI test signing key

This keystore is intentionally committed to the public `validation/gingervm-apk-v0.6.3` branch solely for repeatable test APK signing. It is not a production/release key and must never be reused for a real application release.

The expected APK signer certificate SHA-256 is `398effdd769fa7db5bc6e45622b0d222570ffd0af3d889a8c23d0a82782ccc98`. The workflow uses the key only during the Android APK signing step, masks the test passphrase from Actions output, removes its runner-temporary copy, and uploads only the signed APK and checksum. The keystore, passphrase and other signing files are not packaged in the APK or included in the uploaded artifact.
