use assert_cmd::prelude::*;
use predicates::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn no_arguments() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("encrypted-box")?;
    cmd.assert().failure().stderr(predicate::str::contains(
        "The following required arguments were not provided",
    ));

    Ok(())
}

#[test]
fn no_fields() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("encrypted-box")?;
    cmd.arg("-p").arg("password");
    cmd.assert().failure().stderr(predicate::str::contains(
        "The following required arguments were not provided",
    ));

    Ok(())
}

#[test]
fn no_password_file() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("encrypted-box")?;
    cmd.arg("--password-file").arg("non_existent_file.txt");
    cmd.assert().failure().stderr(predicate::str::contains(
        "The following required arguments were not provided",
    ));

    Ok(())
}

#[test]
fn scheme_out_of_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("encrypted-box")?;
    cmd.arg("-p")
        .arg("password")
        .arg("-f")
        .arg("field")
        .arg("-s")
        .arg("500");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("The scheme index is unsupported!"));

    Ok(())
}

#[test]
fn compare_use_password_to_password_file() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = NamedTempFile::new()?;
    write!(file, "password")?;

    let mut cmd_file = Command::cargo_bin("encrypted-box")?;
    cmd_file
        .arg("--password-file")
        .arg(file.path())
        .arg("-f")
        .arg("field")
        .arg("-s")
        .arg("1");
    let c_file = cmd_file.output()?;

    let mut cmd_line = Command::cargo_bin("encrypted-box")?;
    cmd_line
        .arg("-p")
        .arg("password")
        .arg("-f")
        .arg("field")
        .arg("-s")
        .arg("1");

    let c_line = cmd_line.output()?;

    assert_eq!(c_line, c_file);

    Ok(())
}

#[test]
fn add_many_random_fields() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("encrypted-box")?;
    cmd.arg("-p").arg("password").arg("-f");
    for _i in 1..1000 {
        let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
        cmd.arg(rand_string);
    }

    cmd.assert().success();

    Ok(())
}

#[test]
fn double_password() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("encrypted-box")?;
    cmd.arg("-p")
        .arg("password")
        .arg("-p")
        .arg("another password")
        .arg("-f")
        .arg("field");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("was provided more than once"));

    Ok(())
}

#[test]
fn double_scheme() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("encrypted-box")?;
    cmd.arg("-s")
        .arg("1")
        .arg("-s")
        .arg("2")
        .arg("-p")
        .arg("another password")
        .arg("-f")
        .arg("field");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("was provided more than once"));

    Ok(())
}
