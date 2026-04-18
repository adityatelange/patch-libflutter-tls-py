# patch-flutter-tls

A Python script that patches `libflutter.so` to disable Flutter's TLS verification for Android apps.

## Background

Flutter's TLS verification can cause issues when trying to intercept and analyze network traffic using tools like Burp Suite or Charles Proxy. By patching libflutter.so, you can disable TLS verification and allow these tools to intercept the traffic for analysis.

The script is based on the work of [Jeroen Beckers @TheDauntless](https://github.com/TheDauntless) at https://github.com/NVISOsecurity/disable-flutter-tls-verification. List of offsets are present [here](https://github.com/NVISOsecurity/disable-flutter-tls-verification/blob/4ac95edba90cf48bb8298e6538b6f1e923926dc6/disable-flutter-tls.js#L28-L47). Thanks to Jeroen and NVISO for their work on this topic.

Using a Frida-based approach was crashing the app and sometimes caused the device to reboot. In practice, Frida-based TLS bypass typically also requires a _rooted_ device (or other advanced instrumentation) to reliably hook the right processes/libraries at runtime.

Also, the upstream Frida script is not compatible with Frida 17.x, so I decided to create a patching script that modifies `libflutter.so` directly. This way, you can patch the file _once_ and use it on any device without needing to run a Frida script — including non-rooted devices.

> [!Note]
> After patching and rebuilding/signing the APK, you can capture traffic on non-rooted devices as well; as long as you can route the app's traffic through your proxy (e.g., via Wi‑Fi proxy settings, a VPN-based tunnel, or other traffic redirection).
>
> Patching `libflutter.so` for TLS verification will not make the app proxy-aware. It only disables TLS verification so HTTPS traffic can be intercepted.

Tested on:

- Apktool - v2.12.1
- Python - v3.9
- OS - Linux (Ubuntu 24.04)
- Java - 21.0

## Usage

1. Extract the APK using [`apktool`](https://github.com/ibotpeaches/apktool):

   ```sh
   apktool d --no-res --no-src your_app.apk
   ```

2. Run the patch script:

   ```sh
   python patch_libflutter_tls.py -i path/to/libflutter.so -o path/to/libflutter.so
   ```

   ```sh
   $ python patch_libflutter_tls.py -u -i ext/lib/arm64-v8a/libflutter.so
   [*] In-place update enabled; output will overwrite input file
   [*] Detected architecture: arm64 (e_machine=183)
   [+] Pattern matched (1 hits) for pattern: F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9
      - patching offset 0x71ED88
   [+] Wrote patched file to: ext/lib/arm64-v8a/libflutter.so
   [+] Total patched matches: 1
   ```

   > This will patch the `libflutter.so` file in place.
   > There can be multiple `libflutter.so` files in the APK, so make sure to patch all of them if necessary (e.g., `your_app/lib/armeabi-v7a/libflutter.so`, `your_app/lib/arm64-v8a/libflutter.so`, etc.).

3. Rebuild the APK using apktool:

   ```sh
   apktool b --net-sec-conf your_app -o patched_app.apk
   ```

4. Sign the patched APK using your preferred signing tool.

   > I recommend using [APK Explorer & Editor (AEE)](https://github.com/apk-editor/APK-Explorer-Editor) for this step.

## Options

```sh
$ python patch_libflutter_tls.py -h
usage: patch_libflutter_tls.py [-h] -i INPUT [-o OUTPUT] [-u] [--arch {x86,x64,arm,arm64}] [--thumb]

Patch libflutter.so to disable Flutter TLS verification.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input .so file (libflutter.so)
  -o OUTPUT, --output OUTPUT
                        Output patched .so file (default: <input>.patched.so)
  -u, --inplace         Overwrite input file (write patched output to same path)
  --arch {x86,x64,arm,arm64}
                        Force architecture (optional)
  --thumb               If patching ARM, assemble thumb variant (if using keystone)
```

## Disclaimer

> [!WARNING]
> This script is intended for educational and testing purposes only. Use it responsibly and ensure you have permission to modify the APKs you are working with. The author is not responsible for any misuse of this script.

This script may not work with all versions of Flutter or all devices, and it may cause instability in the app. Use it at your own risk. Always keep a backup of the original `libflutter.so` file before patching.
