{ pkgs ? import <nixpkgs> {}}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    bacon
    tokei
  
    hyperfine

    evcxr
  ];
}
