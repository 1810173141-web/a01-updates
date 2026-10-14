"""Fail-closed, offline release gate. No private key and no third-party Python imports."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from manifest_read import manifest_attributes

CERT = "25280080e854bc7fbbcae86b89b3d7cc0d66d9c1925454f4d97fd4e0eadf8369"
BASE = "https://1810173141-web.github.io/a01-updates/stable"
HERE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def run(argv):
    result = subprocess.run([str(a) for a in argv], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=180)
    print(json.dumps(dict(argv=[str(a) for a in argv], exit_status=result.returncode,
                          stdout=result.stdout, stderr=result.stderr), ensure_ascii=False))
    require(result.returncode == 0, "External verification failed")
    return result.stdout


def verify(release, apk, java, apktool, signer):
    manifest = json.loads((release / "release-manifest.json").read_text(encoding="utf-8"))
    require(manifest["schema"] == 1 and manifest["expiry_ms"] == 4102415999000,
            "Wrong manifest schema or expiry")
    require(manifest["package"] == "com.local.scriptrunner", "Wrong package")
    require(manifest["apk"]["name"] == "update.apk", "Unexpected APK name")
    require(manifest["apk"]["certificate_sha256"] == CERT, "Untrusted release signer")
    require(manifest["version_code"] > manifest["minimum_client_version_code"], "Non-increasing version")
    version = manifest["version_name"]
    require(bool(re.fullmatch(r"[1-9][0-9]{0,3}\.(0|[1-9][0-9]{0,2})\.0", version)), "Not stable version")
    major, minor, patch = map(int, version.split("."))
    require(major * 1000000 + minor * 1000 + patch == manifest["version_code"], "Version/code mismatch")
    data = apk.read_bytes()
    require(len(data) == manifest["apk"]["bytes"], "APK size mismatch")
    require(digest(data) == manifest["apk"]["sha256"], "APK SHA-256 mismatch")
    require(hashlib.md5(data).hexdigest() == manifest["apk"]["md5"], "APK MD5 mismatch")
    chunks = []
    for number, part in enumerate(manifest["parts"], 1):
        require(part["name"] == "update.apk." + str(number).zfill(3), "Non-sequential part name")
        b = (release / part["name"]).read_bytes()
        require(0 < len(b) <= 8 * 1024 * 1024 and len(b) == part["bytes"], "Part size mismatch")
        require(digest(b) == part["sha256"], "Part hash mismatch")
        chunks.append(b)
    require(b"".join(chunks) == data, "Fragments differ from APK")
    require(sorted(p.name for p in release.glob("update.apk.*")) == [p["name"] for p in manifest["parts"]], "Unexpected fragment")
    checkbytes = (release / "check").read_bytes()
    require(digest(checkbytes) == manifest["check_sha256"], "Metadata hash mismatch")
    metadata = json.loads(checkbytes)
    require(metadata["code"] == 1 and metadata["version"] == version, "Metadata version mismatch")
    require(metadata["md5"] == manifest["apk"]["md5"], "Metadata MD5 mismatch")
    require(metadata["download_url"] == BASE + "/update.apk?md5=" + metadata["md5"], "Wrong public route")
    with zipfile.ZipFile(apk) as z:
        require(z.testzip() is None, "Corrupt ZIP")
        attrs = manifest_attributes(z.read("AndroidManifest.xml"), include_application=True)
    require(attrs == {"package": manifest["package"], "versionName": version,
                      "versionCode": manifest["version_code"],
                      "applicationName": "local.runner.RunnerApplication"}, "APK/metadata version or Application entry disagreement")
    output = run([java, "-cp", signer, "com.android.apksigner.ApkSignerTool", "verify", "--verbose", "--print-certs", apk])
    certs = re.findall(r"^Signer #\d+ certificate SHA-256 digest:\s*([a-fA-F0-9:]+)\s*$", output, re.M)
    require([c.replace(":", "").lower() for c in certs] == [CERT], "APK signer mismatch")
    for scheme in (2, 3):
        require(bool(re.search(r"^Verified using v" + str(scheme) + r" scheme .*:\s*true\s*$", output, re.M)), "Missing APK v2/v3 signature")
    run([java, "--class-path", apktool, HERE / "VerifyExpiry2099.java", "--candidate", apk,
         "--cert", HERE / "test_signer.x509.pem"])
    print("RELEASE_GATE=PASS")
    print("RELEASE_VERSION=" + version)
    print("RELEASE_SHA256=" + digest(data))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--java", default="java")
    parser.add_argument("--apktool-jar", type=Path, required=True)
    parser.add_argument("--signer-jar", type=Path, required=True)
    args = parser.parse_args()
    verify(args.release_dir, args.apk, args.java, args.apktool_jar, args.signer_jar)


if __name__ == "__main__":
    main()
