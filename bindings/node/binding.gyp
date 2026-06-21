{
  "variables": {
    # Directory holding libzcio (shared). Override with the ZCIO_LIB_DIR env var
    # (CTest sets it to the real build dir); otherwise default to ../../build.
    "zcio_lib_dir%": "<!(node -p \"process.env.ZCIO_LIB_DIR || require('path').resolve(process.cwd(), '../../build')\")"
  },
  "targets": [
    {
      "target_name": "zcio_native",
      "sources": [ "zcio_addon.c" ],
      "include_dirs": [ "<(module_root_dir)/../../include" ],
      "defines": [ "NAPI_VERSION=8" ],
      "cflags": [ "-std=c11", "-Wall" ],
      "cflags_c": [ "-std=c11", "-Wall" ],
      "libraries": [ "-L<(zcio_lib_dir)", "-lzcio" ],
      "ldflags": [ "-Wl,-rpath,<(zcio_lib_dir)" ],
      "xcode_settings": {
        "OTHER_LDFLAGS": [ "-Wl,-rpath,<(zcio_lib_dir)" ]
      }
    }
  ]
}
