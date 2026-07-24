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
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              (rust-bin.stable."1.92.0".minimal.override {
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
              })
              pkg-config
              b3sum
              taplo
              shellcheck
              markdownlint-cli2
            ];
            buildInputs = with pkgs; [ openssl ];
            PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" [ pkgs.openssl.dev ];
          };
        }
      );
    };
}
