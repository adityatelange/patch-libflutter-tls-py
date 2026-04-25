# patch-flutter-tls

A Python script that patches an APK's bundled `libflutter.so` files to disable Flutter's TLS verification for Android apps.

## Background

Flutter's TLS verification can cause issues when trying to intercept and analyze network traffic using tools like Burp Suite. By patching libflutter.so, you can disable TLS verification and allow these tools to intercept the traffic for analysis.

The script is based on the work of [Jeroen Beckers @TheDauntless](https://github.com/TheDauntless) at https://github.com/NVISOsecurity/disable-flutter-tls-verification. List of offsets are present [here](https://github.com/NVISOsecurity/disable-flutter-tls-verification/blob/4ac95edba90cf48bb8298e6538b6f1e923926dc6/disable-flutter-tls.js#L28-L47). Thanks to Jeroen and NVISO for their work on this topic.

Using a Frida-based approach was crashing the app and sometimes caused the device to reboot. In practice, Frida-based TLS bypass typically also requires a _rooted_ device (or other advanced instrumentation) to reliably hook the right processes/libraries at runtime.

Also, the upstream Frida script is not compatible with Frida 17.x, so I decided to create a patching script that modifies `libflutter.so` directly. This way, you can patch the file _once_ and use it on any device without needing to run a Frida script — including non-rooted devices.

> [!Note]
> After patching and signing the APK, you can capture traffic on non-rooted devices as well; as long as you can route the app's traffic through your proxy (e.g., via Wi‑Fi proxy settings, a VPN-based tunnel, or other traffic redirection).
>
> Patching `libflutter.so` for TLS verification will not make the app proxy-aware. It only disables TLS verification so HTTPS traffic can be intercepted.
> You still need to patch others aspects of the app (e.g., network configuration, certificate pinning, etc.) to ensure the app's traffic is properly routed through your proxy.

## Usage

1. Install the tool with `uv` or run it directly.

   ```sh
   uv install .
   patch-flutter-tls com.app.apk
   ```

   Or run directly:

   ```sh
   python3 patch_libflutter_tls.py com.app.apk
   ```

   This produces a new file next to the input:
   - `com.app_patched.apk`

   The script searches the APK for every `libflutter.so` (across all ABIs such as `arm64-v8a`, `armeabi-v7a`, `x86_64`, etc.), patches each match it finds, and writes an updated APK.

2. Sign the patched APK using your preferred signing tool.

   > Any APK modification invalidates the original signature. You must re-sign before installing.
   > I recommend using [APK Explorer & Editor (AEE)](https://github.com/apk-editor/APK-Explorer-Editor) for this step.

## Options

```sh
$ python3 patch_libflutter_tls.py -h
usage: patch_libflutter_tls.py [-h] apk_path

Patch APK files to disable Flutter TLS verification.

positional arguments:
  apk_path    Input APK file path

optional arguments:
  -h, --help  show this help message and exit
```

## Disclaimer

> [!WARNING]
> This script is intended for educational and testing purposes only. Use it responsibly and ensure you have permission to modify the APKs you are working with. The author is not responsible for any misuse of this script.

This script may not work with all versions of Flutter or all devices, and it may cause instability in the app. Use it at your own risk.
