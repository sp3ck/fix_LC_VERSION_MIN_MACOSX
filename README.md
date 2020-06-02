# fix_LC_VERSION_MIN_MACOSX

Small command-line program to update LC_VERSION_MIN_MACOSX to 10.9 if it is less than 10.9.

## Building

```bash
gcc fix_LC_VERSION_MIN_MACOSX.c -o fixMonoMinVersion
```

## Running

Run it on your application like this:

```bash
fixMonoMinVersion "${APP_PATH}/Contents/Frameworks/MonoEmbedRuntime/osx/libmono.0.dylib"
fixMonoMinVersion "${APP_PATH}/Contents/Frameworks/MonoEmbedRuntime/osx/libMonoPosixHelper.dylib"
```

## History

This code came from a gist that no longer exists (https://gist.github.com/lynnlx/1c15f290383c750abdd9d42e70bd32e4).

The code from that gist seems to have be derived from [this one](https://gist.github.com/landonf/1046134).

Since I pointed to it in a [blog post](https://asmaloney.com/2020/03/howto/notarizing-older-unity-games-on-macos/), I've created this repo to host the code.

For more information on what this does and when it is useful, please see the article [Notarizing Older Unity Games On macOS](https://asmaloney.com/2020/03/howto/notarizing-older-unity-games-on-macos/).
