#!/usr/bin/env python3
"""Fetch a verified simulator artifact, then test native app startup only.

No login, UI taps, simulated messages, device installation, or re-signing.
The built-in GitHub token is used by the fetch phase only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import shutil
import stat
import struct
import subprocess
import time
import zipfile

import inspect_ipa

PIN = 'fb0e62ba8a147f0821da6aa63c09da7d79a10111'
IPA_NAME = 'Telegram-simulator-not-for-iPhone.ipa'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def command_evidence(output, label, status, started_at, elapsed, stdout, stderr):
    if output is None:
        return
    summary = f'[{label}] {status} started={started_at} elapsed={elapsed:.3f}s'
    with (output / 'native-commands.log').open('a', encoding='utf-8') as stream:
        stream.write('\n' + summary + '\n')
        for name, value in (('stdout', stdout), ('stderr', stderr)):
            # TimeoutExpired carries bytes (or None), even with text=True.
            if isinstance(value, bytes):
                value = value.decode('utf-8', errors='replace')
            value = value or ''
            stream.write(f'[{name}; last 16000 characters; truncated={len(value) > 16000}]\n{value[-16000:]}\n')
    print(summary, flush=True)


def command(args, timeout=60, output=None, label=None, include_stderr=False, acceptable_codes=(0,)):
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    started = time.monotonic()
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            command_evidence(output, label or args[0], f'timeout={timeout}s', started_at,
                             time.monotonic() - started, exc.stdout, exc.stderr)
        except Exception:
            # A full/unavailable evidence filesystem must not replace the timeout.
            pass
        raise
    command_evidence(output, label or args[0], f'exit={completed.returncode}', started_at,
                     time.monotonic() - started, completed.stdout, completed.stderr)
    require(completed.returncode in acceptable_codes, f'{label or args[0]} failed with exit {completed.returncode}')
    return (completed.stdout + ('\n' + completed.stderr if include_stderr else '')).strip()


def github(endpoint):
    return json.loads(command(['gh', 'api', endpoint], timeout=60, label='GitHub read API'))


def verify_manifest(download, run_id, source_sha, evidence):
    metadata = json.loads((download / 'manifest.json').read_text())
    require(metadata.get('source_revision') == source_sha, 'Artifact source SHA mismatch')
    require(metadata.get('target') == 'simulator' and metadata.get('configuration') == 'debug_sim_arm64',
            'Only a simulator artifact is accepted')
    require(str(metadata.get('run_id')) == run_id, 'Manifest build run does not match the requested run')
    require(metadata.get('workflow_revision') == evidence['build_workflow_sha'], 'Manifest workflow SHA mismatch')
    if metadata.get('source_kind') == 'baseline':
        require(source_sha == PIN and metadata.get('source_repository') == 'TelegramMessenger/Telegram-iOS',
                'Baseline artifact is not the reviewed upstream pin')
    else:
        require(metadata.get('source_kind') == 'feature' and metadata.get('source_repository') == evidence['repository']
                and source_sha == evidence['build_workflow_sha'], 'Feature artifact source/provenance mismatch')
    ipa = download / IPA_NAME
    require(ipa.is_file() and metadata.get('bytes') == ipa.stat().st_size, 'IPA missing or size mismatch')
    require(metadata.get('sha256') == inspect_ipa.sha256(ipa), 'IPA SHA-256 differs from its manifest')
    return metadata


def fetch(output, run_id, source_sha):
    repository = os.environ.get('GITHUB_REPOSITORY', '')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'Expected repository context missing')
    run = github(f'repos/{repository}/actions/runs/{run_id}')
    require(run.get('status') == 'completed' and run.get('conclusion') == 'success',
            'Requested build run has not completed successfully')
    require(run.get('path', '').split('@')[0] == '.github/workflows/chat-timeline.yml',
            'Requested run is not the reviewed build workflow')
    require(run.get('head_repository', {}).get('full_name') == repository, 'Build run belongs to another repository')
    artifacts = github(f'repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100')
    require(artifacts.get('total_count', 0) <= 100, 'Unexpected artifact pagination; refusing ambiguous selection')
    pattern = rf'Telegram-(baseline|feature)-simulator-{re.escape(run_id)}'
    candidates = [item for item in artifacts.get('artifacts', []) if re.fullmatch(pattern, item['name']) and not item['expired']]
    require(len(candidates) == 1, 'Expected exactly one unexpired simulator build artifact')
    artifact = candidates[0]
    require(artifact['created_at'] >= run['run_started_at'], 'Artifact predates the current build attempt')
    require(artifact.get('size_in_bytes', 0) <= 3 * 1024 ** 3, 'Artifact is unexpectedly large')
    evidence = {'repository': repository, 'build_run_id': run_id, 'build_run_attempt': run.get('run_attempt'),
                'build_workflow_sha': run['head_sha'], 'expected_source_sha': source_sha,
                'artifact_id': artifact['id'], 'artifact_name': artifact['name'], 'build_conclusion': 'success'}
    outer = output / 'downloaded-artifact.zip'
    with outer.open('wb') as stream:
        result = subprocess.run(['gh', 'api', f'repos/{repository}/actions/artifacts/{artifact["id"]}/zip'],
                                stdout=stream, stderr=subprocess.PIPE, timeout=180)
    require(result.returncode == 0, 'Artifact download failed')
    download = output / 'download'
    download.mkdir()  # Never mix files from an earlier artifact.
    allowed = {IPA_NAME, 'manifest.json', 'preflight.json'}
    with zipfile.ZipFile(outer) as archive:
        members = archive.infolist()
        require(len(members) <= 3 and len({item.filename for item in members}) == len(members),
                'Unexpected artifact ZIP inventory')
        for item in members:
            require(item.filename in allowed and not stat.S_ISLNK(item.external_attr >> 16)
                    and not item.flag_bits & 1 and item.file_size <= 2 * 1024 ** 3,
                    'Unsafe or unexpected outer artifact member')
            if item.filename != IPA_NAME:
                require(item.file_size <= inspect_ipa.MAX_PLIST, 'Artifact metadata is oversized')
        require(archive.testzip() is None, 'Outer artifact CRC failure')
        for item in members:
            with archive.open(item) as source, (download / item.filename).open('wb') as destination:
                shutil.copyfileobj(source, destination, 1024 * 1024)
    metadata = verify_manifest(download, run_id, source_sha, evidence)
    evidence.update({'result': 'pass', 'source_revision': source_sha, 'ipa_sha256': metadata['sha256'],
                     'artifact_archive_sha256': inspect_ipa.sha256(outer)})
    save(output / 'fetch-report.json', evidence)


def selected_runtime(runtimes, device_types):
    installed = [item for item in runtimes['runtimes'] if item.get('isAvailable')
                 and item.get('identifier', '').startswith('com.apple.CoreSimulator.SimRuntime.iOS-')]
    require(installed, 'No installed available iOS simulator runtime')
    installed.sort(key=lambda item: (item['version'] == '27.1', inspect_ipa.version(item['version'])), reverse=True)
    known = {item['identifier']: item for item in device_types['devicetypes']}
    candidates = [(runtime, known[item['identifier']]) for runtime in installed
                  for item in runtime.get('supportedDeviceTypes', [])
                  if item['identifier'] in known and item.get('productFamily') == 'iPhone']
    require(candidates, 'Runtimes do not advertise any installed compatible iPhone device type')
    # Runtime 27.1 on this image advertises only iPhone Duo; 27.0 supports iPhone 15.
    # Honor the requested phone when any installed runtime actually supports it.
    return next((pair for pair in candidates if pair[1]['identifier'] ==
                 'com.apple.CoreSimulator.SimDeviceType.iPhone-15'), candidates[0])


def safe_for_ditto(ipa):
    """Validate paths and symlink graph before macOS ditto preserves native ZIP metadata."""
    with zipfile.ZipFile(ipa) as archive:
        links, paths, regular_files = {}, set(), set()
        for item in archive.infolist():
            path = item.filename.rstrip('/')
            require(path and not path.startswith('/') and '\\' not in path and ':' not in path
                    and all(part not in ('', '.', '..') for part in path.split('/')), 'Unsafe IPA extraction path')
            require(path.casefold() not in paths, 'Duplicate IPA extraction path')
            paths.add(path.casefold())
            mode = item.external_attr >> 16
            kind = stat.S_IFMT(mode)
            require(kind in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK), 'Special device/FIFO member refused')
            if stat.S_ISLNK(mode):
                require(item.file_size <= 4096, 'Oversized symlink')
                target = archive.read(item).decode('utf-8')
                require(target and not target.startswith('/') and '\\' not in target and ':' not in target
                        and '\0' not in target and '..' not in target.split('/'), 'Unsafe or parent-traversing symlink target')
                links[path] = target
            elif not item.is_dir():
                regular_files.add(path)
        # The default macOS volume is case-insensitive; check aliases on that basis.
        links = {path.casefold(): target.casefold() for path, target in links.items()}
        regular_files = {path.casefold() for path in regular_files}
        all_names = [item.filename.rstrip('/').casefold() for item in archive.infolist()]
        available_paths = paths | {str(parent) for path in all_names for parent in PurePosixPath(path).parents
                                   if str(parent) != '.'}
        for path in all_names:
            parents = [str(parent) for parent in PurePosixPath(path).parents if str(parent) != '.']
            require(not any(parent in links or parent in regular_files for parent in parents),
                    'Archive entry traverses a symlink or file parent')
        for origin in links:
            resolved = origin
            for _ in range(40):
                parts = resolved.split('/')
                prefix = next(('/'.join(parts[:index]) for index in range(1, len(parts) + 1)
                               if '/'.join(parts[:index]) in links), None)
                if prefix is None:
                    break
                suffix = resolved[len(prefix):].lstrip('/')
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(prefix), links[prefix], suffix))
                require(resolved != '..' and not resolved.startswith('../') and not resolved.startswith('/'),
                        'Symlink resolves outside extraction directory')
            else:
                raise RuntimeError('Cyclic or excessively deep symlink chain')
            require(resolved.casefold() in available_paths, 'Dangling IPA symlink')


def check_process(pid, executable):
    os.kill(pid, 0)
    process = command(['ps', '-p', str(pid), '-o', 'stat=', '-o', 'comm='], timeout=10)
    fields = process.split(None, 1)
    require(len(fields) == 2 and 'Z' not in fields[0] and PurePosixPath(fields[1].strip()).name == executable,
            'Launched PID is dead, a zombie, or no longer identifies the application executable')


def cleanup(output):
    marker = output / 'created-simulator.json'
    if not marker.is_file():
        return
    data = json.loads(marker.read_text())
    require(data.get('owner_run_id') == os.environ.get('GITHUB_RUN_ID'), 'Simulator ownership marker mismatch')
    device_id = data['device_id']
    require(re.fullmatch(r'[0-9A-Fa-f-]{36}', device_id), 'Invalid created simulator ID')
    devices = json.loads(command(['xcrun', 'simctl', 'list', 'devices', '-j'], timeout=30))
    existing = next((item for group in devices['devices'].values() for item in group if item['udid'] == device_id), None)
    if existing:
        require(existing['name'] == data['name'], 'Created simulator name no longer matches')
        if existing.get('state') != 'Shutdown':
            command(['xcrun', 'simctl', 'shutdown', device_id], timeout=30, output=output, label='shutdown owned simulator')
        command(['xcrun', 'simctl', 'delete', device_id], timeout=30, output=output, label='delete owned simulator')
    save(output / 'cleanup.json', {'result': 'pass', 'only_created_simulator': True, 'device_id': device_id})


def crash_summary(output, executable, start, device_id):
    # Fresh runner, new empty simulator; nevertheless never upload full crash reports.
    roots = [Path.home() / 'Library/Logs/DiagnosticReports',
             Path.home() / f'Library/Developer/CoreSimulator/Devices/{device_id}/data/Library/Logs/CrashReporter']
    files = []
    for root in roots:
        if root.is_dir():
            files.extend(path for path in root.iterdir() if path.is_file() and path.name.startswith(executable)
                         and path.suffix in ('.ips', '.crash') and path.stat().st_mtime >= start)
    result = []
    for path in sorted(files, key=lambda item: item.stat().st_mtime, reverse=True)[:5]:
        item = {'file': path.name, 'bytes': path.stat().st_size, 'sha256': inspect_ipa.sha256(path)}
        if path.stat().st_size <= 512 * 1024:
            text = path.read_text(errors='replace')
            try:
                data = json.loads(text.split('\n', 1)[1]) if path.suffix == '.ips' else None
                if isinstance(data, dict):
                    item['exception'] = {key: data.get('exception', {}).get(key) for key in ('type', 'signal', 'codes')}
                    item['termination'] = {key: data.get('termination', {}).get(key) for key in ('namespace', 'code', 'indicator')}
                else:
                    item['exception_lines'] = [line[:500] for line in text.splitlines()
                        if line.startswith(('Exception Type:', 'Exception Codes:', 'Termination Reason:', 'Triggered by Thread:'))][:8]
            except (ValueError, IndexError, AttributeError):
                item['details'] = 'unparsed; original report not uploaded'
        result.append(item)
    save(output / 'crash-summary.json', {'matching_recent_reports': result, 'full_reports_uploaded': False})
    return result


def install_diagnostics(output, device_id, bundle_identifier):
    # Read-only, fresh unauthenticated simulator; no full sysdiagnose/log archive.
    # Every probe has its own cap. Unsupported or stalled diagnostics remain unknown.
    report = {'scope': 'installation_failure_diagnostics', 'install_retried': False,
              'disk_free_bytes': shutil.disk_usage(output).free, 'checks': []}
    if hasattr(os, 'getloadavg'):
        report['host_load_average'] = list(os.getloadavg())
    probes = [
        ('app container readback', ['xcrun', 'simctl', 'get_app_container', device_id, bundle_identifier, 'app'], 15),
        ('simulator installation log', ['xcrun', 'simctl', 'spawn', device_id, 'log', 'show',
            '--style', 'compact', '--last', '5m', '--info', '--predicate',
            'process == "installd" OR process == "installcoordinationd" OR subsystem CONTAINS[c] "MobileInstallation"'], 20),
        ('host CoreSimulator log', ['/usr/bin/log', 'show', '--style', 'compact', '--last', '5m',
            '--info', '--predicate', 'process == "CoreSimulatorService" OR subsystem BEGINSWITH "com.apple.CoreSimulator"'], 20),
    ]
    for label, args, timeout in probes:
        item = {'probe': label, 'timeout_seconds': timeout, 'result': 'unknown'}
        try:
            value = command(args, timeout=timeout, output=output, label=label,
                            include_stderr=label != 'app container readback')
            item['result'] = 'collected'
            if label == 'app container readback':
                item['container_directory_exists'] = bool(value) and Path(value).is_dir()
        except Exception as exc:
            item['failure'] = f'{type(exc).__name__}: {exc}'[:1000]
        report['checks'].append(item)
    save(output / 'install-diagnostics.json', report)


def install_app(output, device_id, app_path, bundle_identifier):
    try:
        command(['xcrun', 'simctl', 'install', device_id, str(app_path)],
                timeout=120, output=output, label='install')
    except Exception:
        try:
            install_diagnostics(output, device_id, bundle_identifier)
        except Exception as exc:
            # Diagnostics must never replace the original install failure.
            print(f'Installation diagnostics unavailable: {type(exc).__name__}: {exc}', flush=True)
        raise


def run_smoke(output, run_id, source_sha):
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'Native Apple Silicon macOS required')
    require(os.environ.get('GITHUB_RUN_ID', '').isdigit(), 'This helper requires its GitHub job context')
    evidence = json.loads((output / 'fetch-report.json').read_text())
    require(evidence['repository'] == os.environ.get('GITHUB_REPOSITORY') and evidence['build_run_id'] == run_id,
            'Fetched artifact context mismatch')
    metadata = verify_manifest(output / 'download', run_id, source_sha, evidence)
    runtime, device_type = selected_runtime(
        json.loads(command(['xcrun', 'simctl', 'list', 'runtimes', '-j'])),
        json.loads(command(['xcrun', 'simctl', 'list', 'devicetypes', '-j'])))
    ipa = output / 'download' / IPA_NAME
    audit = inspect_ipa.inspect(ipa, output / 'download/manifest.json', source_sha, runtime['version'], 'simulator')
    save(output / 'ipa-audit.json', audit)
    require(not audit['errors'], 'IPA static audit has known failures')
    require(not any(item['code'] == 'macho_platform_not_proven_by_lc_build_version' for item in audit['unknowns']),
            'Simulator platform could not be established from Mach-O')
    main_app = next(item for item in audit['bundles'] if item['kind'] == 'main_app')
    safe_for_ditto(ipa)
    extraction = output / 'extracted'
    extraction.mkdir()
    command(['ditto', '-x', '-k', str(ipa), str(extraction)], timeout=120, output=output, label='ditto IPA extraction')
    app_path = extraction / main_app['path']
    require(os.access(app_path / main_app['executable'], os.X_OK), 'Native executable mode was not preserved')
    help_text = []
    for action in ('create', 'boot', 'bootstatus', 'install', 'launch', 'io'):
        help_text.append(command(['xcrun', 'simctl', 'help', action], timeout=30, include_stderr=True))
    for args in (['xcrun', 'simctl', 'help', 'get_app_container'], ['xcrun', 'simctl', 'help', 'spawn'],
                 ['/usr/bin/log', 'help', 'show']):
        try:
            help_text.append(command(args, timeout=10, include_stderr=True))
        except Exception as exc:
            help_text.append(f'Optional diagnostic help unavailable: {args}: {type(exc).__name__}: {exc}')
    # Apple's ditto prints usage with exit 1. This exception is diagnostic-only;
    # extraction, boot, install and launch continue to require exit 0.
    help_text.append(command(['ditto', '-h'], timeout=30, include_stderr=True, acceptable_codes=(0, 1)))
    (output / 'simctl-help.txt').write_text('\n'.join(help_text), encoding='utf-8')
    name = 'ChatTimelineSmoke-' + os.environ['GITHUB_RUN_ID']
    device_id = command(['xcrun', 'simctl', 'create', name, device_type['identifier'], runtime['identifier']], timeout=45)
    require(re.fullmatch(r'[0-9A-Fa-f-]{36}', device_id), 'simctl create did not return a device ID')
    save(output / 'created-simulator.json', {'device_id': device_id, 'name': name, 'owner_run_id': os.environ['GITHUB_RUN_ID']})
    report = {'result': 'fail', 'scope': 'native_application_startup_only', 'source_build_run_id': run_id,
              'source_revision': source_sha, 'artifact_id': evidence['artifact_id'], 'ipa_sha256': metadata['sha256'],
              'smoke_workflow_revision': os.environ.get('GITHUB_SHA'), 'device_type': device_type['identifier'],
              'runtime': {'identifier': runtime['identifier'], 'version': runtime['version'], 'build': runtime.get('buildversion')},
              'simulator_id': device_id, 'bundle_identifier': main_app['bundle_identifier'],
              'telegram_login_performed': False, 'feature_tested': False, 'iphone_tested': False,
              'screenshots_visually_reviewed': False, 'screenshot_display': 'primary',
              'screenshots': [], 'process_alive_after_20_seconds': False}
    started = time.time()
    try:
        command(['xcrun', 'simctl', 'boot', device_id], timeout=45, output=output, label='boot')
        command(['xcrun', 'simctl', 'bootstatus', device_id, '-b'], timeout=180, output=output, label='bootstatus')
        install_app(output, device_id, app_path, main_app['bundle_identifier'])
        launched = command(['xcrun', 'simctl', 'launch', device_id, main_app['bundle_identifier']], timeout=45, output=output, label='launch')
        match = re.search(re.escape(main_app['bundle_identifier']) + r':\s*(\d+)\s*$', launched)
        require(match, 'simctl launch did not return the application PID')
        pid = int(match.group(1))
        report['process_id'] = pid
        observed = time.monotonic()
        for second in (2, 20):
            while time.monotonic() - observed < second:
                os.kill(pid, 0)
                time.sleep(min(1.0, max(0.0, second - (time.monotonic() - observed))))
            check_process(pid, main_app['executable'])
            screenshot = output / f'startup-{second:02d}s.png'
            command(['xcrun', 'simctl', 'io', device_id, 'screenshot', '--type=png', '--display=primary', str(screenshot)],
                    timeout=30, output=output, label='native screenshot')
            with screenshot.open('rb') as stream:
                header = stream.read(24)
            require(header[:8] == b'\x89PNG\r\n\x1a\n' and len(header) == 24, 'simctl did not produce a PNG')
            width, height = struct.unpack('>II', header[16:24])
            report['screenshots'].append({'file': screenshot.name, 'seconds_after_launch': round(time.monotonic() - observed, 2),
                                          'width': width, 'height': height, 'sha256': inspect_ipa.sha256(screenshot)})
            check_process(pid, main_app['executable'])
        report['process_alive_after_20_seconds'] = True
        report['observed_seconds'] = round(time.monotonic() - observed, 2)
        require(not crash_summary(output, main_app['executable'], started, device_id), 'A matching application crash report was produced')
        report['result'] = 'pass'
    except Exception as exc:
        report['failure'] = f'{type(exc).__name__}: {exc}'[:2000]
        raise
    finally:
        if not (output / 'crash-summary.json').exists():
            crash_summary(output, main_app['executable'], started, device_id)
        save(output / 'smoke-manifest.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('fetch', 'run', 'cleanup'))
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.run_id.isdigit() and re.fullmatch(r'[a-f0-9]{40}', args.source_sha), 'Run ID/full source SHA invalid')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    try:
        if args.operation == 'fetch':
            fetch(output, args.run_id, args.source_sha)
        elif args.operation == 'cleanup':
            cleanup(output)
        else:
            run_smoke(output, args.run_id, args.source_sha)
    except Exception as exc:
        filename = 'fetch-report.json' if args.operation == 'fetch' else 'cleanup.json' if args.operation == 'cleanup' else 'smoke-manifest.json'
        if not (output / filename).exists():
            save(output / filename, {'result': 'fail', 'stage': args.operation, 'source_build_run_id': args.run_id,
                                     'source_revision': args.source_sha, 'failure': f'{type(exc).__name__}: {exc}'[:2000]})
        print(f'{args.operation} failed: {type(exc).__name__}: {exc}', flush=True)
        return 1
    print(f'{args.operation} passed; this workflow tests application startup only.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
