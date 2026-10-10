use super::read;

#[test]
fn postinst_creates_only_a_missing_private_data_directory() {
	let postinst = read("debian/epistle.postinst");
	assert!(postinst.contains("if [ ! -e /var/lib/glyndor/epistle/data ] && [ ! -L /var/lib/glyndor/epistle/data ]; then\n\t\tinstall -d -m 0700 -o glyndor-epistle -g glyndor-epistle \\\n\t\t\t/var/lib/glyndor/epistle/data\n\tfi"),
        "postinst must create only a missing data directory with service ownership and mode 0700");
}

#[test]
fn postinst_preserves_existing_data_and_installs_missing_data_privately() {
	use std::os::unix::fs::{PermissionsExt, symlink};
	use std::process::Command;
	for existing in ["missing", "directory", "file", "symlink"] {
		let dir = tempfile::tempdir().unwrap();
		let data = dir.path().join("data");
		match existing {
			"directory" => {
				std::fs::create_dir(&data).unwrap();
				std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o750)).unwrap();
			}
			"file" => std::fs::write(&data, "preserve").unwrap(),
			"symlink" => symlink(dir.path().join("absent"), &data).unwrap(),
			_ => {}
		}
		let bin = dir.path().join("bin");
		std::fs::create_dir(&bin).unwrap();
		let install = bin.join("install");
		std::fs::write(&install, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$INSTALL_LOG\"\nfor arg do last=$arg; done\nexec /usr/bin/install -d -m 0700 \"$last\"\n").unwrap();
		std::fs::set_permissions(&install, std::fs::Permissions::from_mode(0o755)).unwrap();
		let postinst = read("debian/epistle.postinst");
		let block: String = postinst
			.lines()
			.skip_while(|line| !line.contains("if [ ! -e /var/lib/glyndor/epistle/data ]"))
			.take_while(|line| line.trim() != "fi")
			.chain(std::iter::once("fi"))
			.collect::<Vec<_>>()
			.join("\n")
			.replace("/var/lib/glyndor/epistle/data", data.to_str().unwrap());
		let log = dir.path().join("install.log");
		let output = Command::new("/bin/sh")
			.args(["-c", &block])
			.env("PATH", &bin)
			.env("INSTALL_LOG", &log)
			.output()
			.unwrap();
		assert_eq!(
			output.status.code(),
			Some(0),
			"data provisioning must succeed"
		);
		if existing == "missing" {
			assert_eq!(
				std::fs::metadata(&data).unwrap().permissions().mode() & 0o777,
				0o700,
				"new data directories must be owner-only"
			);
			assert_eq!(
				std::fs::read_to_string(log).unwrap(),
				format!(
					"-d\n-m\n0700\n-o\nglyndor-epistle\n-g\nglyndor-epistle\n{}\n",
					data.display()
				),
				"postinst must request service ownership for the new data directory"
			);
		} else {
			assert!(
				!log.exists(),
				"postinst must never touch existing data paths"
			);
		}
	}
}
