{
  "targets": [
    {
      "target_name": "zcio_native",
      "sources": [ "zcio_addon.c" ],
      "include_dirs": [ "<(module_root_dir)/../../include" ],
      "defines": [ "NAPI_VERSION=8" ],
      "cflags": [ "-std=c11", "-Wall" ],
      "cflags_c": [ "-std=c11", "-Wall" ],
      "libraries": [ "-L<(module_root_dir)/../../build", "-lzcio" ],
      "ldflags": [ "-Wl,-rpath,<(module_root_dir)/../../build" ],
      "xcode_settings": {
        "OTHER_LDFLAGS": [ "-Wl,-rpath,<(module_root_dir)/../../build" ]
      }
    }
  ]
}
