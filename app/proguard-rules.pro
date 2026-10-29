# ProGuard / R8 rules for BettingShield
-keep class com.bettingshield.app.data.** { *; }
-keep class com.bettingshield.app.updates.BlocklistPayload { *; }
-keepclassmembers class * extends androidx.room.RoomDatabase { *; }
