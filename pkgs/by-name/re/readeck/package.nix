{
  fetchFromGitea,
  fetchNpmDeps,
  buildGoModule,
  nodejs,
  npmHooks,
  lib,
}:

let

  file-compose = buildGoModule {
    pname = "file-compose";
    version = "unstable-2023-10-21";

    src = fetchFromGitea {
      domain = "codeberg.org";
      owner = "readeck";
      repo = "file-compose";
      rev = "afa938655d412556a0db74b202f9bcc1c40d8579";
      hash = "sha256-rMANRqUQRQ8ahlxuH1sWjlGpNvbReBOXIkmBim/wU2o=";
    };

    vendorHash = "sha256-Qwixx3Evbf+53OFeS3Zr7QCkRMfgqc9hUA4eqEBaY0c=";
  };
in

buildGoModule rec {
  pname = "readeck";
  # TODO: move to regular versions when v0.17 is released
  # This unreleased version contains the changes necessary to
  # set the secret key via environment variable, which is
  # necessary for the NixOS module.
  version = "unstable-2024-12-04";

  src = fetchFromGitea {
    domain = "codeberg.org";
    owner = "readeck";
    repo = "readeck";
    rev = "789c17e523b953596f0af28afa11ab93ba235118";
    hash = "sha256-cJA5Jm4/LqXBLmDVxMJtyLDBVdpMqDrb6En0svYuzA0=";
  };

  nativeBuildInputs = [
    nodejs
    npmHooks.npmConfigHook
  ];

  npmRoot = "web";

  NODE_PATH = "$npmDeps";

  preBuild = ''
    make web-build
    ${file-compose}/bin/file-compose -format json docs/api/api.yaml docs/assets/api.json
    go run ./tools/docs docs/src docs/assets
  '';

  tags = [
    "netgo"
    "osusergo"
    "sqlite_omit_load_extension"
    "sqlite_foreign_keys"
    "sqlite_json1"
    "sqlite_fts5"
    "sqlite_secure_delete"
  ];

  overrideModAttrs = oldAttrs: {
    # Do not add `npmConfigHook` to `goModules`
    nativeBuildInputs = lib.remove npmHooks.npmConfigHook oldAttrs.nativeBuildInputs;
    # Do not run `preBuild` when building `goModules`
    preBuild = null;
  };

  npmDeps = fetchNpmDeps {
    src = "${src}/web";
    hash = "sha256-D9G1m8nChHNAlLKfhph4gJoV8aKA2le0dZtDHobotlU=";
  };

  vendorHash = "sha256-MG1EuWTJ71uK5VIcZ5Rao52NeNd/ENPAmPI53xeQCWI=";

  meta = with lib; {
    description = "Web application that lets you save the readable content of web pages you want to keep forever.";
    mainProgram = "readeck";
    homepage = "https://readeck.org/";
    changelog = "https://github.com/readeck/readeck/releases/tag/${version}";
    license = licenses.agpl3Only;
    maintainers = with maintainers; [ julienmalka ];
  };

}
