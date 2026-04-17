# patch-flutter-tls

A Python script that patches `libflutter.so` to disable Flutter's TLS verification for Android apps.

## Background

Flutter's TLS verification can cause issues when trying to intercept and analyze network traffic using tools like Burp Suite or Charles Proxy. By patching libflutter.so, you can disable TLS verification and allow these tools to intercept the traffic for analysis.

The script is based on the work of [Jeroen Beckers @TheDauntless](https://github.com/TheDauntless) at https://github.com/NVISOsecurity/disable-flutter-tls-verification. List of offsets are present [here](https://github.com/NVISOsecurity/disable-flutter-tls-verification/blob/4ac95edba90cf48bb8298e6538b6f1e923926dc6/disable-flutter-tls.js#L28-L47). Thanks to Jeroen and NVISO for their work on this topic.

Using this script with Frida was crashing the app and sometimes caused the device to reboot. Also, the Frida script is not compatible with Frida 17.x, so I decided to create a patching script that modifies `libflutter.so` directly. This way, you can patch the file once and use it on any device without needing to run a Frida script.

Note: Patching `libflutter.so` for TLS verification will not make the app proxy-aware. It will only disable TLS verification, allowing you to intercept the traffic. You may still need to tunnel/force the app's traffic through other means (e.g., using a VPN or modifying the app's network configuration) to ensure that the traffic is routed through your proxy tool.

## Usage

1. Extract the APK using [`apktool`](https://github.com/ibotpeaches/apktool):
   ```sh
   apktool d --no-res --no-src your_app.apk
   ```
2. Run the patch script:
   ```sh
   python patch_libflutter.py -i path/to/libflutter.so -o path/to/libflutter.so
   ```
   > This will patch the `libflutter.so` file in place.
   > There can be multiple `libflutter.so` files in the APK, so make sure to patch all of them if necessary (e.g., `your_app/lib/armeabi-v7a/libflutter.so`, `your_app/lib/arm64-v8a/libflutter.so`, etc.).
3. Rebuild the APK using apktool:
   ```sh
   apktool b --net-sec-conf your_app -o patched_app.apk
   ```
4. Sign the patched APK using your preferred signing tool.
   > I recommend using [APK Explorer & Editor (AEE)](https://github.com/apk-editor/APK-Explorer-Editor) for this step.

## Disclaimer

This script is intended for educational and testing purposes only. Use it responsibly and ensure you have permission to modify the APKs you are working with. The author is not responsible for any misuse of this script.

This script may not work with all versions of Flutter or all devices, and it may cause instability in the app. Use it at your own risk. Always keep a backup of the original `libflutter.so` file before patching.
