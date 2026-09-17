# No release-build shrinking rules needed yet -- isMinifyEnabled is false
# above. If that's ever flipped on, MusterJson/MusterClient use no
# reflection so shouldn't need keep rules, but WorkManager/AndroidX may;
# revisit then rather than guessing rules for a config that isn't in use.
