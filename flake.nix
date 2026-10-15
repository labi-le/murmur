{
  description = "murmur dev shells";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/643809054d65fdd466a63e3155b8c498cb483c04";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      devShells.${system} = {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            stdenv.cc
            cargo-audit
            cargo-deny
            cargo-machete
            cargo-nextest
            sccache
            typos
            mold
            tokei
            heaptrack
            perf
            cargo-flamegraph
          ];

          CARGO_INCREMENTAL = "0";
          RUST_BACKTRACE = "1";
          RUSTC_WRAPPER = "${pkgs.sccache}/bin/sccache";
          SCCACHE_CACHE_SIZE = "20G";
          SCCACHE_DIR = "/var/cache/sccache";
          SCCACHE_SERVER_UDS = "/run/sccache/sccache.sock";
          RUSTFLAGS = "-Clink-arg=-fuse-ld=mold -Clink-arg=-B${pkgs.mold}/bin";
        };

        aarch64-musl =
          let
            cross = pkgs.pkgsCross.aarch64-multiplatform-musl;
            targetPrefix = cross.stdenv.cc.targetPrefix;
          in
          pkgs.mkShell {
            packages = [
              cross.buildPackages.rustc
              cross.buildPackages.cargo
              cross.stdenv.cc
              pkgs.cmake
              pkgs.perl
              pkgs.pkg-config
              pkgs.sccache
            ];

            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = "${targetPrefix}gcc";
            CC_aarch64_unknown_linux_musl = "${targetPrefix}gcc";
            CXX_aarch64_unknown_linux_musl = "${targetPrefix}g++";
            AR_aarch64_unknown_linux_musl = "${targetPrefix}ar";
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C target-feature=+crt-static";
            CARGO_INCREMENTAL = "0";
            RUSTFLAGS = "-C target-feature=+crt-static";
          };

        windows =
          let
            cross = pkgs.pkgsCross.mingwW64;
            targetPrefix = cross.stdenv.cc.targetPrefix;
            pthreads = cross.windows.pthreads;
          in
          pkgs.mkShell {
            packages = [
              cross.buildPackages.rustc
              cross.buildPackages.cargo
              cross.buildPackages.clippy
              cross.stdenv.cc
              pkgs.wine64
              pkgs.nasm
              pkgs.cmake
              pkgs.perl
              pkgs.sccache
            ];

            CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "${targetPrefix}gcc";
            CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER = "wine";
            CC_x86_64_pc_windows_gnu = "${targetPrefix}gcc";
            CXX_x86_64_pc_windows_gnu = "${targetPrefix}g++";
            AR_x86_64_pc_windows_gnu = "${targetPrefix}ar";
            CFLAGS_x86_64_pc_windows_gnu = "-I${pthreads}/include -Wno-stringop-overflow -Wno-array-bounds -Wno-restrict -O2 -U_FORTIFY_SOURCE";
            CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS = "-L native=${pthreads}/lib";
            CARGO_INCREMENTAL = "0";
            RUST_BACKTRACE = "1";
            RUSTC_WRAPPER = "${pkgs.sccache}/bin/sccache";
            SCCACHE_CACHE_SIZE = "20G";
            SCCACHE_DIR = "/var/cache/sccache";
            SCCACHE_SERVER_UDS = "/run/sccache/sccache.sock";
      };
    };
};
}
