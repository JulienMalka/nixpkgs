{ system ? builtins.currentSystem
, config ? { }
, pkgs ? import ../.. { inherit system config; }
}:

with import ../lib/testing-python.nix { inherit system pkgs; };
with pkgs.lib;

let
  tpmSocketPath = "/tmp/swtpm-sock";
  tpmDeviceModels = {
    x86_64-linux = "tpm-tis";
    aarch64-linux = "tpm-tis-device";
  };

  ovmfpkg = pkgs.OVMF.override { tpmSupport = true; debug = true; sourceDebug = false; };
  bios = if pkgs.stdenv.isAarch64 then "QEMU_EFI.fd" else "OVMF.fd";
  makeConfig = pkgs.writeText "configuration.nix" ''
    { config, lib, pkgs, ... }:
    {
      imports = [
        ./hardware-configuration.nix
        <nixpkgs/nixos/modules/testing/test-instrumentation.nix>
      ];
      networking.hostName = "installed";
      boot.loader.systemd-boot.enable = true;

      #boot.kernelParams = [ "systemd.log_level=debug" ];
      boot.initrd = {
      availableKernelModules = [ "tpm_tis" ];
      systemd.enable = true;
      };
      # To ensure that we can rebuild the grub configuration on the nixos-rebuild
      system.extraDependencies = with pkgs; [ stdenvNoCC ];
      documentation.enable = false;
      hardware.enableAllFirmware = lib.mkForce false;
      networking.interfaces."eth1".useDHCP = false;
      boot.initrd.secrets."/etc/secret" = ./secret;
      boot.loader.useSystemdStub = true;
      boot.initrd.systemd.services.test = {
        before = [ "initrd.target" ];
        after = [
        "systemd-udev-settle.service"
        "systemd-modules-load.service"
        "systemd-ask-password-console.service" ];
        wants = [ "systemd-udev-settle.service" ];
        wantedBy = [ "initrd.target" ];
        script = "cat $CREDENTIALS_DIRECTORY/mdr";
        serviceConfig.Type = "oneshot";
        serviceConfig.LoadCredentialEncrypted = [ "mdr:/.extra/credentials/mdr.cred" ];
      };

    }
  '';
  common = {
    virtualisation.useBootLoader = true;
    virtualisation.useEFIBoot = true;
    boot.loader.systemd-boot.enable = true;
    boot.loader.efi.canTouchEfiVariables = true;
    environment.systemPackages = [ pkgs.efibootmgr ];
  };
in
{
  basic = makeTest {
    name = "systemd-boot";
    meta.maintainers = with pkgs.lib.maintainers; [ danielfullmer ];

    nodes.machine = common;

    testScript = ''
      machine.start()
      machine.wait_for_unit("multi-user.target")

      machine.succeed("test -e /boot/loader/entries/nixos-generation-1.conf")

      # Ensure we actually booted using systemd-boot
      # Magic number is the vendor UUID used by systemd-boot.
      machine.succeed(
          "test -e /sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
      )

      # "bootctl install" should have created an EFI entry
      machine.succeed('efibootmgr | grep "Linux Boot Manager"')
    '';
  };

  stub = makeTest {
    name = "systemd-stub";
    meta.maintainers = with pkgs.lib.maintainers; [ danielfullmer ];

    nodes.machine = { pkgs, lib, ... }: {
      imports = [ common ];
      boot.loader.useSystemdStub = true;
      virtualisation.mountHostNixStore = true;
      virtualisation.memorySize = 8000;
    };

    testScript = ''
      machine.start()
      machine.wait_for_unit("multi-user.target")
    '';
  };

  stub-secrets = makeTest {
    name = "systemd-stub-secrets";
    meta.maintainers = with pkgs.lib.maintainers; [ danielfullmer ];

    nodes.installer = { pkgs, ... }: {
      imports = [
        ../modules/profiles/installation-device.nix
        ../modules/profiles/base.nix
        ./common/auto-format-root-device.nix
      ];

      #boot.kernelParams = [ "systemd.log_level=debug" ];
      virtualisation.mountHostNixStore = true;
      #virtualisation.useBootLoader = true;
      #virtualisation.useEFIBoot = true;
      boot.loader.systemd-boot.enable = true;
      virtualisation.forwardPorts = [
        { from = "host"; host.port = 3333; guest.port = 3333; }
      ];

      boot.loader.efi.canTouchEfiVariables = true;

      boot.initrd = {
        availableKernelModules = [ "tpm_tis" ];
        systemd.enable = true;
      };

      nix.settings = {
        substituters = mkForce [ ];
        hashed-mirrors = null;
        connect-timeout = 1;
      };


      system.extraDependencies = with pkgs;
        let
          python = python3Minimal.override { self = python; includeSiteCustomize = true; };
        in

        [
          (pkgs.systemdMinimal.override {
            withEfi = true;
            withBootloader = true;
            withUkify = true;
          })
          (gdb.override { pythonSupport = false; hostCpuOnly = true; })
          bintools
          systemd
          systemdMinimal
          which
          brotli
          brotli.dev
          xz
          brotli.lib
          curl
          desktop-file-utils
          docbook5
          docbook_xsl_ns
          kbd.dev
          klibc
          glibc
          kmod.dev
          zlib
          libarchive.dev
          libxml2.bin
          libxslt.bin
          nixos-artwork.wallpapers.simple-dark-gray-bottom
          ntp
          perlPackages.ListCompare
          perlPackages.XMLLibXML
          python3Minimal
          (python.withPackages (p: [ p.mistune ]))
          mypy
          shared-mime-info
          sudo
          texinfo
          unionfs-fuse
          xorg.lndir
        ];


      hardware.enableAllFirmware = mkForce false;

      virtualisation = {
        # In systemdStage1, also automatically format the device backing the
        # root filesystem.
        fileSystems."/".autoFormat = true;

        # Builds stuff in the VM, needs more juice.
        diskSize = 8 * 1024;
        cores = 50;
        memorySize = 100000;

        # Use a small /dev/vdb as the root disk for the
        # installer. This ensures the target disk (/dev/vda) is
        # the same during and after installation.
        emptyDiskImages = [ 512 ];
        rootDevice = "/dev/vdb";
        bootLoaderDevice = "/dev/vda";
        qemu.diskInterface = "virtio";
        qemu.options = [
          "-chardev socket,path=/home/luj/dev/nixpkgs/hello,id=gdb,server=on"
          "-device isa-serial,index=3,chardev=gdb"
          "-chardev socket,id=chrtpm,path=$TMPDIR/swtpm-sock"
          "-tpmdev emulator,id=tpm0,chardev=chrtpm"
          "-device tpm-tis,tpmdev=tpm0"
        ];
      };
    };

    testScript = ''
      import subprocess

      class Tpm:
            def __init__(self, state_dir):
                self.start(state_dir)

            def start(self, state_dir):
                self.proc = subprocess.Popen(["${pkgs.swtpm}/bin/swtpm",
                    "socket",
                    "--tpmstate", "dir={}".format(os.path.join(state_dir, "swtpm")),
                    "--ctrl", "type=unixio,path={}".format(os.path.join(state_dir, "swtpm-sock")),
                    "--tpm2"
                    ])

                # Check whether starting swtpm failed
                try:
                    exit_code = self.proc.wait(timeout=0.2)
                    if exit_code is not None and exit_code != 0:
                        raise Exception("failed to start swtpm")
                except subprocess.TimeoutExpired:
                    pass

            """Check whether the swtpm process exited due to an error"""
            def check(self):
                exit_code = self.proc.poll()
                if exit_code is not None and exit_code != 0:
                    raise Exception("swtpm process died")


      def assemble_qemu_flags(state_dir):
          flags = "-cpu max"
          ${if (system == "x86_64-linux" || system == "i686-linux")
            then ''flags += " -m 1024"''
            else ''flags += " -m 768 -enable-kvm -machine virt,gic-version=host"''
          }
          tpm_socket = os.path.join(state_dir, "swtpm-sock")
          flags += " -chardev socket,id=chrtpm,path={} -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0".format(tpm_socket)
          flags += " -chardev socket,path=/home/luj/dev/nixpkgs/hello,id=gdb,server=on"
          flags += " -device isa-serial,index=3,chardev=gdb"

          return flags


      qemu_flags = {"qemuFlags": assemble_qemu_flags(machine.state_dir)}

      import os

      image_dir = machine.state_dir
      disk_image = os.path.join(image_dir, "installer.qcow2")

      hd_flags = {
          "hdaInterface": "virtio",
          "hda": disk_image,
      }
      ${optionalString true ''
        hd_flags.update(
            bios="${ovmfpkg.fd}/FV/${bios}"
        )''
      }
      default_flags = {**hd_flags, **qemu_flags}


      def create_machine_named(name):
          return create_machine({**default_flags, "name": name})

      os.mkdir(os.path.join(image_dir, "swtpm"))
      tpm = Tpm(machine.state_dir)
      tpm.check()
      installer.start()
      installer.wait_for_unit("multi-user.target")


      with subtest("Check whether TPM device exists"):
        installer.succeed("test -e /dev/tpm0")
        installer.succeed("test -e /dev/tpmrm0")

      with subtest("Check whether systemd-creds detects TPM2 correctly"):
        cmd = "systemd-creds has-tpm2"
        machine.log(f"Running \"{cmd}\"")
        (status, _) = machine.execute(cmd)

      machine.succeed(
          "flock /dev/vda parted --script /dev/vda -- mklabel gpt"
          + " mkpart ESP fat32 1M 100MiB"  # /boot
          + " set 1 boot on"
          + " mkpart primary linux-swap 100MiB 1024MiB"
          + " mkpart primary ext2 1024MiB -1MiB",  # /
          "udevadm settle",
          "mkswap /dev/vda2 -L swap",
          "swapon -L swap",
          "mkfs.ext3 -L nixos /dev/vda3",
          "mount LABEL=nixos /mnt",
          "mkfs.vfat -n BOOT /dev/vda1",
          "mkdir -p /mnt/boot",
          "mount LABEL=BOOT /mnt/boot",
      )

      with subtest("Create the NixOS configuration"):
          installer.succeed("nixos-generate-config --root /mnt")
          installer.succeed("cat /mnt/etc/nixos/hardware-configuration.nix >&2")
          installer.copy_from_host(
              "${makeConfig}",
              "/mnt/etc/nixos/configuration.nix"
              )
          installer.copy_from_host("${pkgs.writeText "secret" "secret"}", "/mnt/etc/nixos/secret")


      with subtest("Perform the installation"):
          installer.succeed("nixos-install --root /mnt --no-root-passwd --no-channel-copy >&2")

      with subtest("Shutdown system after installation"):
          installer.succeed("umount -R /mnt")
          installer.succeed("sync")
          installer.shutdown()


      tpm = Tpm(machine.state_dir)
      tpm.check()
      machine = create_machine_named("installed")
      machine.wait_for_unit("multi-user.target")



    '';
  };


  # Check that specialisations create corresponding boot entries.
  specialisation = makeTest {
    name = "systemd-boot-specialisation";
    meta.maintainers = with pkgs.lib.maintainers; [ lukegb ];

    nodes.machine = { pkgs, lib, ... }: {
      imports = [ common ];
      specialisation.something.configuration = { };
    };

    testScript = ''
      machine.start()
      machine.wait_for_unit("multi-user.target")

      machine.succeed(
          "test -e /boot/loader/entries/nixos-generation-1-specialisation-something.conf"
      )
      machine.succeed(
          "grep -q 'title NixOS (something)' /boot/loader/entries/nixos-generation-1-specialisation-something.conf"
      )
    '';
  };

  # Boot without having created an EFI entry--instead using default "/EFI/BOOT/BOOTX64.EFI"
  fallback = makeTest {
    name = "systemd-boot-fallback";
    meta.maintainers = with pkgs.lib.maintainers; [ danielfullmer ];

    nodes.machine = { pkgs, lib, ... }: {
      imports = [ common ];
      boot.loader.efi.canTouchEfiVariables = mkForce false;
    };

    testScript = ''
      machine.start()
      machine.wait_for_unit("multi-user.target")

      machine.succeed("test -e /boot/loader/entries/nixos-generation-1.conf")

      # Ensure we actually booted using systemd-boot
      # Magic number is the vendor UUID used by systemd-boot.
      machine.succeed(
          "test -e /sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
      )

      # "bootctl install" should _not_ have created an EFI entry
      machine.fail('efibootmgr | grep "Linux Boot Manager"')
    '';
  };

  update = makeTest {
    name = "systemd-boot-update";
    meta.maintainers = with pkgs.lib.maintainers; [ danielfullmer ];

    nodes.machine = common;

    testScript = ''
      machine.succeed("mount -o remount,rw /boot")

      # Replace version inside sd-boot with something older. See magic[] string in systemd src/boot/efi/boot.c
      machine.succeed(
          """
        find /boot -iname '*boot*.efi' -print0 | \
        xargs -0 -I '{}' sed -i 's/#### LoaderInfo: systemd-boot .* ####/#### LoaderInfo: systemd-boot 000.0-1-notnixos ####/' '{}'
      """
      )

      output = machine.succeed("/run/current-system/bin/switch-to-configuration boot")
      assert "updating systemd-boot from 000.0-1-notnixos to " in output, "Couldn't find systemd-boot update message"
    '';
  };

  memtest86 = makeTest {
    name = "systemd-boot-memtest86";
    meta.maintainers = with pkgs.lib.maintainers; [ Enzime ];

    nodes.machine = { pkgs, lib, ... }: {
      imports = [ common ];
      boot.loader.systemd-boot.memtest86.enable = true;
    };

    testScript = ''
      machine.succeed("test -e /boot/loader/entries/memtest86.conf")
      machine.succeed("test -e /boot/efi/memtest86/memtest.efi")
    '';
  };

  netbootxyz = makeTest {
    name = "systemd-boot-netbootxyz";
    meta.maintainers = with pkgs.lib.maintainers; [ Enzime ];

    nodes.machine = { pkgs, lib, ... }: {
      imports = [ common ];
      boot.loader.systemd-boot.netbootxyz.enable = true;
    };

    testScript = ''
      machine.succeed("test -e /boot/loader/entries/o_netbootxyz.conf")
      machine.succeed("test -e /boot/efi/netbootxyz/netboot.xyz.efi")
    '';
  };

  entryFilename = makeTest {
    name = "systemd-boot-entry-filename";
    meta.maintainers = with pkgs.lib.maintainers; [ Enzime ];

    nodes.machine = { pkgs, lib, ... }: {
      imports = [ common ];
      boot.loader.systemd-boot.memtest86.enable = true;
      boot.loader.systemd-boot.memtest86.entryFilename = "apple.conf";
    };

    testScript = ''
      machine.fail("test -e /boot/loader/entries/memtest86.conf")
      machine.succeed("test -e /boot/loader/entries/apple.conf")
      machine.succeed("test -e /boot/efi/memtest86/memtest.efi")
    '';
  };

  extraEntries = makeTest {
    name = "systemd-boot-extra-entries";
    meta.maintainers = with pkgs.lib.maintainers; [ Enzime ];

    nodes.machine = { pkgs, lib, ... }: {
      imports = [ common ];
      boot.loader.systemd-boot.extraEntries = {
        "banana.conf" = ''
          title banana
        '';
      };
    };

    testScript = ''
      machine.succeed("test -e /boot/loader/entries/banana.conf")
      machine.succeed("test -e /boot/efi/nixos/.extra-files/loader/entries/banana.conf")
    '';
  };

  extraFiles = makeTest {
    name = "systemd-boot-extra-files";
    meta.maintainers = with pkgs.lib.maintainers; [ Enzime ];

    nodes.machine = { pkgs, lib, ... }: {
      imports = [ common ];
      boot.loader.systemd-boot.extraFiles = {
        "efi/fruits/tomato.efi" = pkgs.netbootxyz-efi;
      };
    };

    testScript = ''
      machine.succeed("test -e /boot/efi/fruits/tomato.efi")
      machine.succeed("test -e /boot/efi/nixos/.extra-files/efi/fruits/tomato.efi")
    '';
  };

  switch-test = makeTest {
    name = "systemd-boot-switch-test";
    meta.maintainers = with pkgs.lib.maintainers; [ Enzime ];

    nodes = {
      inherit common;

      machine = { pkgs, nodes, ... }: {
        imports = [ common ];
        boot.loader.systemd-boot.extraFiles = {
          "efi/fruits/tomato.efi" = pkgs.netbootxyz-efi;
        };

        # These are configs for different nodes, but we'll use them here in `machine`
        system.extraDependencies = [
          nodes.common.system.build.toplevel
          nodes.with_netbootxyz.system.build.toplevel
        ];
      };

      with_netbootxyz = { pkgs, ... }: {
        imports = [ common ];
        boot.loader.systemd-boot.netbootxyz.enable = true;
      };
    };

    testScript = { nodes, ... }:
      let
        originalSystem = nodes.machine.system.build.toplevel;
        baseSystem = nodes.common.system.build.toplevel;
        finalSystem = nodes.with_netbootxyz.system.build.toplevel;
      in
      ''
        machine.succeed("test -e /boot/efi/fruits/tomato.efi")
        machine.succeed("test -e /boot/efi/nixos/.extra-files/efi/fruits/tomato.efi")

        with subtest("remove files when no longer needed"):
            machine.succeed("${baseSystem}/bin/switch-to-configuration boot")
            machine.fail("test -e /boot/efi/fruits/tomato.efi")
            machine.fail("test -d /boot/efi/fruits")
            machine.succeed("test -d /boot/efi/nixos/.extra-files")
            machine.fail("test -e /boot/efi/nixos/.extra-files/efi/fruits/tomato.efi")
            machine.fail("test -d /boot/efi/nixos/.extra-files/efi/fruits")

        with subtest("files are added back when needed again"):
            machine.succeed("${originalSystem}/bin/switch-to-configuration boot")
            machine.succeed("test -e /boot/efi/fruits/tomato.efi")
            machine.succeed("test -e /boot/efi/nixos/.extra-files/efi/fruits/tomato.efi")

        with subtest("simultaneously removing and adding files works"):
            machine.succeed("${finalSystem}/bin/switch-to-configuration boot")
            machine.fail("test -e /boot/efi/fruits/tomato.efi")
            machine.fail("test -e /boot/efi/nixos/.extra-files/efi/fruits/tomato.efi")
            machine.succeed("test -e /boot/loader/entries/o_netbootxyz.conf")
            machine.succeed("test -e /boot/efi/netbootxyz/netboot.xyz.efi")
            machine.succeed("test -e /boot/efi/nixos/.extra-files/loader/entries/o_netbootxyz.conf")
            machine.succeed("test -e /boot/efi/nixos/.extra-files/efi/netbootxyz/netboot.xyz.efi")
      '';
  };

  # Some UEFI firmwares fail on large reads. Now that systemd-boot loads initrd
  # itself, systems with such firmware won't boot without this fix
  uefiLargeFileWorkaround = makeTest {
    name = "uefi-large-file-workaround";

    nodes.machine = { pkgs, ... }: {
      imports = [ common ];
      virtualisation.efi.OVMF = pkgs.OVMF.overrideAttrs (old: {
        # This patch deliberately breaks the FAT driver in EDK2 to
        # exhibit (part of) the firmware bug that we are testing
        # for. Files greater than 10MiB will fail to be read in a
        # single Read() call, so systemd-boot will fail to load the
        # initrd without a workaround. The number 10MiB was chosen
        # because if it were smaller than the kernel size, even the
        # LoadImage call would fail, which is not the failure mode
        # we're testing for. It needs to be between the kernel size
        # and the initrd size.
        patches = old.patches or [ ] ++ [ ./systemd-boot-ovmf-broken-fat-driver.patch ];
      });
    };

    testScript = ''
      machine.wait_for_unit("multi-user.target")
    '';
  };
}
