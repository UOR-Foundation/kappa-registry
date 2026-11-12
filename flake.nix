{
  description = "kappa-registry - a conforming kappa-Distribution /v2/ registry";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    konductor = {
      url = "github:braincraftio/konductor";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The standard library every Kappa build compiles against: std
    # `hashmap_bucket_access` and alloc `btree_stepped_cursor` on top of
    # rust-lang/rust db8f076. `nix flake update rust-fork` follows the branch.
    rust-fork = {
      url = "github:usrbinkat/rust/feat/bounded-collection-access";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      konductor,
      rust-fork,
      ...
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [
            konductor.inputs.rust-overlay.overlays.default
            konductor.overlays.default
          ];
        };
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          # The one Kappa toolchain: nightly 2026-10-04 is built from
          # rust-lang/rust db8f076, the fork's base, so compiler and library
          # come from the same commit. std is rebuilt from rust-fork with
          # `-Zbuild-std`, which reads std source only from
          # <sysroot>/lib/rustlib/src/rust/library (cargo
          # src/compiler/standard_lib.rs). dcbor's `custom-std-collections`
          # (bounded std HashMap bucket access) requires it, and every crate
          # of the workspace compiles against it.
          nightly = pkgs.rust-bin.nightly."2026-10-04";
          # The official component keeps its vendored crates.io sources
          # (library/vendor, library/.cargo/config.toml) and submodule
          # contents; the fork's library/ is laid over it.
          forkedRustSrc = pkgs.runCommand "rust-src-bounded-collection-access" { } ''
            cp -R --no-preserve=mode,ownership ${nightly.rust-src} $out
            cp -R --no-preserve=mode,ownership ${rust-fork}/library/. \
              $out/lib/rustlib/src/rust/library/
          '';
          # The library revision builds compile against, which `rustc
          # --version` (the compiler's base commit) does not name; kappa-perf
          # records it in every calibration record's toolchain.
          stdSource = "github:usrbinkat/rust/${rust-fork.rev}";
          rustToolchain =
            (nightly.default.override {
              extensions = [
                "rust-analyzer"
                "clippy"
                "rustfmt"
              ];
              targets = [
                "x86_64-unknown-linux-musl"
                "aarch64-unknown-linux-musl"
              ];
            }).overrideAttrs
              (old: {
                paths = old.paths ++ [ "${forkedRustSrc}" ];
              });
          hostTarget = pkgs.stdenv.hostPlatform.rust.rustcTarget;
          # A real executable, so `nix develop --command cargo` and the
          # Justfile both reach it. External subcommands receive the build
          # flags themselves: Cargo's leading --config arguments are not
          # forwarded by cargo-clippy. A caller that names its own --target
          # (the musl release builds) keeps it; build-std applies to that
          # target too.
          cargo = pkgs.writeShellScriptBin "cargo" ''
            case "''${1:-}" in
              clippy)
                shift
                for arg in "$@"; do
                  if [ "$arg" = --target ] || [ "''${arg#--target=}" != "$arg" ]; then
                    exec ${rustToolchain}/bin/cargo clippy -Zbuild-std=std,panic_abort "$@"
                  fi
                done
                exec ${rustToolchain}/bin/cargo clippy \
                  -Zbuild-std=std,panic_abort --target ${hostTarget} "$@"
                ;;
            esac
            for arg in "$@"; do
              if [ "$arg" = --target ] || [ "''${arg#--target=}" != "$arg" ]; then
                exec ${rustToolchain}/bin/cargo \
                  --config 'unstable.build-std=["std","panic_abort"]' "$@"
              fi
            done
            exec ${rustToolchain}/bin/cargo \
              --config 'unstable.build-std=["std","panic_abort"]' \
              --config 'build.target="${hostTarget}"' "$@"
          '';
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              cargo
              rustToolchain
              just
              pkg-config
              protobuf
              cmake
              b3sum
              taplo
              shellcheck
              markdownlint-cli2
              # The openssl CLI, for inspecting certificates and TLS endpoints.
              openssl
              # Assembles ISA-L's multi-buffer SHA-256 kernels (rekindle-hash),
              # the reference the digest floors are judged against.
              nasm
            ];
            buildInputs = with pkgs; [ openssl ];
            RUSTC = "${rustToolchain}/bin/rustc";
            RUSTDOC = "${rustToolchain}/bin/rustdoc";
            RUSTFMT = "${rustToolchain}/bin/rustfmt";
            KAPPA_STD_SOURCE = stdSource;
            shellHook = ''
              # The cargo wrapper precedes the toolchain's own cargo. Cargo
              # prepends its home bin directory when it is absent from PATH;
              # include it explicitly after the selected toolchain.
              export PATH="${cargo}/bin:${rustToolchain}/bin:$PATH:''${CARGO_HOME:-$HOME/.cargo}/bin"
            '';
            PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" [ pkgs.openssl.dev ];
          };

          # Coverage-guided fuzzing under AddressSanitizer: the same compiler
          # and patched std, with cargo-fuzz, which passes `-Zsanitizer`
          # itself (cargo-fuzz 0.13.2 src/project.rs).
          fuzz = pkgs.mkShell {
            nativeBuildInputs = [
              cargo
              rustToolchain
              pkgs.cargo-fuzz
              pkgs.just
            ];
            RUSTC = "${rustToolchain}/bin/rustc";
            RUSTDOC = "${rustToolchain}/bin/rustdoc";
            RUSTFMT = "${rustToolchain}/bin/rustfmt";
            KAPPA_STD_SOURCE = stdSource;
            shellHook = ''
              export PATH="${cargo}/bin:${rustToolchain}/bin:$PATH"
            '';
          };
        }
      );
    };
}
