{
  description = "kappa-registry - a conforming kappa-Distribution /v2/ registry";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    konductor = {
      url = "github:braincraftio/konductor";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      konductor,
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
          rustToolchain = pkgs.rust-bin.stable."1.98.1".default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
              "rustfmt"
            ];
            targets = [
              "x86_64-unknown-linux-musl"
              "aarch64-unknown-linux-musl"
            ];
          };
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
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
            shellHook = ''
              # Cargo prepends its home bin directory when it is absent from
              # PATH. Include it explicitly after the selected toolchain.
              export PATH="${rustToolchain}/bin:$PATH:''${CARGO_HOME:-$HOME/.cargo}/bin"
            '';
            PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" [ pkgs.openssl.dev ];
          };

          # Coverage-guided fuzzing under AddressSanitizer. cargo-fuzz passes
          # `-Zsanitizer` (cargo-fuzz 0.13.2 src/project.rs), so this shell
          # carries the newest nightly the locked rust-overlay can build.
          fuzz =
            let
              nightlyToolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default);
            in
            pkgs.mkShell {
              nativeBuildInputs = [
                nightlyToolchain
                pkgs.cargo-fuzz
                pkgs.just
              ];
              # The default shell exports its stable compiler through these;
              # an enclosing shell's values must not leak into fuzz builds.
              RUSTC = "${nightlyToolchain}/bin/rustc";
              RUSTDOC = "${nightlyToolchain}/bin/rustdoc";
              RUSTFMT = "${nightlyToolchain}/bin/rustfmt";
              shellHook = ''
                export PATH="${nightlyToolchain}/bin:$PATH"
              '';
            };
        }
      );
    };
}
