#!/usr/bin/env python3
"""Private, explicitly supplied owner-profile build. Never an installable artifact.

No Apple password, private signing key, or API-secret discovery. Runner output is
encrypted to a separately generated local recipient before artifact upload.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import zipfile

import bootstrap
from private_cleanup import PrivateCleanupError, cleanup_private


class PrivateBuildRejected(RuntimeError):
    pass


def decode_input(raw: str) -> tuple[bytes, str, bytes]:
    if not raw or len(raw.encode('utf-8')) > 48_000:
        raise PrivateBuildRejected('Owner input is missing or exceeds the supported size.')
    try:
        data = json.loads(raw)
        if set(data) != {'version', 'profile_der_b64', 'device', 'recipient_certificate_pem'}:
            raise ValueError()
        if data['version'] != 1 or type(data['version']) is not int:
            raise ValueError()
        profile = base64.b64decode(data['profile_der_b64'], validate=True)
        device = data['device']
        recipient = data['recipient_certificate_pem'].encode('ascii')
        if not 128 < len(profile) <= 32_768:
            raise ValueError()
        if not isinstance(device, str) or not re.fullmatch(r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}', device):
            raise ValueError()
        if (not recipient.startswith(b'-----BEGIN CERTIFICATE-----\n')
                or recipient.count(b'-----BEGIN CERTIFICATE-----') != 1
                or not recipient.rstrip().endswith(b'-----END CERTIFICATE-----')
                or len(recipient) > 8192 or b'PRIVATE KEY' in recipient):
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        raise PrivateBuildRejected('Owner input has an unsupported format.') from None
    return profile, device, recipient


def run_private(args: list[str], *, cwd: Path, log: Path, timeout: int) -> None:
    # Do not relay compiler diagnostics: they can contain provisioning identifiers.
    with log.open('ab') as stream:
        process = subprocess.Popen(args, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            returncode = process.wait(timeout=timeout)
        except BaseException:
            # The wrapper runs Bazel in batch mode. Its session owns the build
            # children; stop them before touching their private working directory.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
            raise
    if returncode:
        raise PrivateBuildRejected('Private build operation failed; its raw log is not published.')


def encrypt_artifact(payload: Path, recipient: Path, output: Path, *, outcome: str = 'signing_input') -> dict:
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    destination = output / 'Chat-Timeline-private-result.zip.p7m'
    # CMS encrypts to a public recipient certificate. Its private key stays local.
    # The public receipt hashes the ciphertext; it is not a signed provenance claim.
    process = subprocess.run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc',
                              '-in', str(payload), '-outform', 'DER',
                              '-out', str(destination), str(recipient)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if process.returncode or not destination.is_file() or not destination.stat().st_size:
        destination.unlink(missing_ok=True)
        raise PrivateBuildRejected('Artifact encryption failed; no plaintext artifact is uploaded.')
    receipt = {'format': 'CMS EnvelopedData DER; AES-256-CBC',
               'sha256': bootstrap.sha256(destination), 'bytes': destination.stat().st_size,
               'source_revision': os.environ['EXPECTED_REVISION'],
               'run_id': os.environ.get('GITHUB_RUN_ID'),
               'device_installable_directly': False, 'device_tested': False,
               'plaintext_uploaded': False, 'outcome': outcome}
    (output / 'encrypted-artifact.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def execute(source: Path, private: Path, output: Path) -> None:
    api_source = os.environ.get('API_SOURCE', '')
    if api_source not in ('secrets', 'upstream-test'):
        raise PrivateBuildRejected('API source must be explicitly selected; no fallback is performed.')
    os.umask(0o077)
    # New, dedicated directory only. Never reuse an unrelated temporary folder.
    private.mkdir(mode=0o700, parents=False, exist_ok=False)
    raw = os.environ.pop('CHAT_TIMELINE_OWNER_INPUT', '')
    profile, device, recipient = decode_input(raw)
    del raw
    signing = private / 'signing'
    profiles = signing / 'profiles'
    profiles.mkdir(mode=0o700, parents=True)
    profile_path = profiles / 'Telegram.mobileprovision'
    profile_path.write_bytes(profile)
    (signing / 'selecteddevice.txt').write_text(device + '\n', encoding='ascii')
    del profile
    recipient_path = private / 'recipient.pem'
    recipient_path.write_bytes(recipient)
    report_directory = private / 'preflight'
    expected = os.environ['EXPECTED_REVISION']
    if not re.fullmatch(r'[0-9a-f]{40}', expected):
        raise PrivateBuildRejected('Expected revision is invalid.')
    # Same toolchain, resource and provenance guards as the existing device build.
    # This explicit mode validates the actual profile instead of expired fixtures.
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            bootstrap.prepare(source, report_directory, 'device', api_source, expected,
                              'owner-deferred', profile_path, device)
    finally:
        # The validated private configuration is the build input. Compiler and
        # encryption subprocesses do not need API credentials in their environment.
        os.environ.pop('TELEGRAM_API_ID', None)
        os.environ.pop('TELEGRAM_API_HASH', None)
    print('Owner profile and build preflight passed. Starting the device build.', flush=True)
    run_private([sys.executable, '-u', 'build-system/Make/Make.py',
                 '--bazelUserRoot=' + str(private / 'bazel'), 'build',
                 '--configurationPath=' + str(report_directory / 'configuration.json'),
                 '--codesigningInformationPath=' + str(signing), '--deferredOwnerSigning',
                 '--configuration=release_arm64', '--buildNumber=' + os.environ['GITHUB_RUN_NUMBER']],
                cwd=source, log=private / 'build.log', timeout=285 * 60)
    print('Device compilation finished; verifying and preparing signing input.', flush=True)
    # Repeat expiry/trust after compilation, before handling any build result.
    from owner_profile import verify_profile
    verified = verify_profile(profile_path, device)
    from owner_signing_input import package_input
    prepared = private / 'prepared'
    package_input(source=source, output=prepared, verified_owner=verified,
                  expected_revision=expected)
    archive = private / 'private-build.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(prepared.iterdir()):
            if not path.is_file() or path.is_symlink():
                raise PrivateBuildRejected('Unexpected package output.')
            bundle.write(path, path.name)
    encrypt_artifact(archive, recipient_path, output)
    print('Encrypted signing input prepared. Installation and login remain unverified.', flush=True)


def protect_failure_log(private: Path, output: Path) -> None:
    log, recipient = private / 'build.log', private / 'recipient.pem'
    if output.exists() or not log.is_file() or not recipient.is_file():
        return
    # Keep failed-build evidence available privately without publishing its text.
    archive = private / 'failed-build.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(log, 'private-build.log')
    encrypt_artifact(archive, recipient, output, outcome='build_failed_private_log')


def cleanup_configuration(source: Path) -> None:
    build_input = source / 'build-input'
    if not build_input.exists():
        return
    if build_input.is_symlink() or build_input.resolve().parent != source:
        raise PrivateBuildRejected('Refusing an unexpected configuration cleanup location.')
    for name in ('configuration-repository', 'configuration-repository-workdir'):
        path = build_input / name
        if path.is_symlink():
            raise PrivateBuildRejected('Refusing a symlink configuration cleanup target.')
        if path.is_dir():
            shutil.rmtree(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--private', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    source, private, output = (value.resolve() for value in
                               (arguments.source, arguments.private, arguments.output))
    runner_temp = Path(os.environ['RUNNER_TEMP']).resolve()
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    if source.parent != workspace or source.name != 'source':
        raise SystemExit('Source must be the fresh dedicated workflow checkout.')
    # Cleanup only a validated, dedicated child, never a caller-selected parent.
    if private.parent != runner_temp or private.name != 'chat-timeline-owner-private':
        raise SystemExit('Private directory must be the dedicated runner temporary child.')
    if output.parent != runner_temp or output.name != 'chat-timeline-owner-encrypted':
        raise SystemExit('Output directory must be the dedicated encrypted-artifact child.')
    if private.exists() or output.exists():
        raise SystemExit('Fresh temporary directories are required.')
    exit_code = 0
    try:
        execute(source, private, output)
    except BaseException:
        # Never serialize exception text, a profile, config, or private compiler log.
        print('Owner build did not finish. No raw private diagnostics are published.', file=sys.stderr)
        try:
            protect_failure_log(private, output)
        except Exception:
            print('Private failure evidence could not be encrypted.', file=sys.stderr)
        exit_code = 1
    finally:
        try:
            cleanup_configuration(source)
        except BaseException:
            print('Private generated configuration cleanup failed.', file=sys.stderr)
            exit_code = 1
        finally:
            try:
                cleanup_private(private, runner_temp)
            except PrivateCleanupError as error:
                print(f'Private temporary directory cleanup failed. stage={error.stage} reason={error.reason}.', file=sys.stderr)
                exit_code = 1
            except BaseException:
                print('Private temporary directory cleanup failed.', file=sys.stderr)
                exit_code = 1
    if exit_code:
        raise SystemExit(exit_code)


if __name__ == '__main__':
    main()
