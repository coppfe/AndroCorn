## Config values means

Emulator Config probably about package

```js
{
	"_pkg_name":"parent_pkg_name",
	"pkg_name": "main_pkg_name",
	"uid": 0,                                                       // can be random int
	"pid": 0,                                                       // can be random int
	"ppid": 0,                                                      // can be random int
	"debuggable": true | false,                                     // doesn't implemented
	"start_timestamp": 1774458140,                                  // Freeze time
	"build_at": 1678884069,                                         // Package install time. Probably bad idea bcs stat_to_memory using it for every file
    "sign_hex": "apk_hex",
    "version_code": 1,

	"device": {                                                     // your device stat
		"memory": {
			"ram_total_mb": 8192,
			"ram_free_percent_start": 45,
			"swap_total_mb": 2048
		},

		"kernel": {                                                 // google pixel
            "release": "3.18.31-g7915904",
            "version": "#1 SMP PREEMPT Thu Jun 15 16:34:02 UTC 2017"
        }

		"net": {
			"ip": "192.168.1.52",
			"mac": "cc:fa:a6:00:8a:a9",
			"dns": "8.8.8.8",
			"ssid": "Massive",
			"gateway": "89.207.132.170"
		},

        "android_id": "hex",                                         // random by default
																	 // config: am get-config. device additional info
		"config": "mcc250-mnc01-ru-rRU,ldltr,sw360dp,w360dp,h640dp,320dpi,nokeys,vga,notouch,keysasaccent\nabi: arm64-v8a,armeabi-v7a,armeabi"
	}
}
```