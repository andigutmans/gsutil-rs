#!/usr/lib/google-cloud-sdk/platform/bundledpythonunix/bin/python3
"""Black-box runner for official upstream Python gsutil integration tests against Rust gsutil.

Imports upstream `gslib/tests/test_*.py` unmodified from the installed Google Cloud SDK
(`/usr/lib/google-cloud-sdk/platform/gsutil`), monkeypatches ONLY
`GsUtilIntegrationTestCase.RunGsUtil` (and `gslib.tests.util.GetGsutilCommand`) in memory
so every `self.RunGsUtil(...)` subprocess executes our Rust `gsutil` binary, while all
upstream test assertions, setup, and teardown remain 100% untouched.

Supports two backends:
  --backend mock : Spawns `gsutil-parity --serve-mock-tls` (2-tier CA self-signed TLS
                   in-memory GCS server) with isolated temp `.boto` and mock ADC.
  --backend live : Runs against a real GCP project (`--project` or `GSUTIL_TEST_PROJECT`),
                   using `/usr/bin/ecp_http_proxy` automatically if present.
"""

import argparse
import collections
import concurrent.futures
import datetime
import importlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
import urllib.parse
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GSUTIL_DIR = os.environ.get('GSUTIL_DIR', '/usr/lib/google-cloud-sdk/platform/gsutil')
DEFAULT_RUST_BIN = os.path.join(REPO_ROOT, 'target', 'release', 'gsutil')
DEFAULT_PARITY_BIN = os.path.join(REPO_ROOT, 'target', 'debug', 'gsutil-parity')

DEFAULT_STAGE2_MODULES = [
    'test_gsutil',
    'test_help',
    'test_hash',
    'test_cat',
    'test_stat',
    'test_du',
    'test_ls',
    'test_mb',
    'test_rb',
    'test_rm',
    'test_setmeta',
    'test_compose',
    'test_cp',
    'test_mv',
    'test_rsync',
    'test_rewrite',
    'test_versioning',
    'test_cors',
    'test_lifecycle',
    'test_logging',
    'test_web',
    'test_label',
    'test_defstorageclass',
    'test_pap',
    'test_ubla',
    'test_bucketpolicyonly',
    'test_rpo',
    'test_autoclass',
    'test_requester_pays',
    'test_retention',
    'test_acl',
    'test_defacl',
    'test_iam',
    'test_signurl',
    'test_hmac',
    'test_notification',
    'test_kms',
    'test_Doption',
    'test_naming',
]


def _pick_free_port():
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(('127.0.0.1', 0))
    return sock.getsockname()[1]


def _start_mock_backend(parity_bin, project_id):
  tmpdir = tempfile.mkdtemp(prefix='gsutil-rs-upstream-mock-')
  ca_pem = os.path.join(tmpdir, 'mock_ca.pem')
  state_dir = os.path.join(tmpdir, 'state')
  fake_home = os.path.join(tmpdir, 'home')
  os.makedirs(state_dir, exist_ok=True)
  os.makedirs(fake_home, exist_ok=True)

  proc = subprocess.Popen(
      [parity_bin, '--serve-mock-tls', '--port', '0', '--ca-out', ca_pem],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      text=True,
  )
  ready_line = proc.stdout.readline().strip()
  if not ready_line.startswith('READY https://127.0.0.1:'):
    stderr_out = proc.stderr.read() if proc.stderr else ''
    proc.terminate()
    shutil.rmtree(tmpdir, ignore_errors=True)
    raise RuntimeError(
        f'Mock TLS server failed to start. stdout={ready_line!r} stderr={stderr_out!r}'
    )
  port = int(ready_line.rsplit(':', 1)[1])

  adc_path = os.path.join(tmpdir, 'adc.json')
  with open(adc_path, 'w', encoding='utf-8') as f:
    json.dump(
        {
            'type': 'authorized_user',
            'client_id': 'mock-client-id',
            'client_secret': 'mock-client-secret',
            'refresh_token': 'mock-refresh-token',
            'token_uri': f'https://127.0.0.1:{port}/oauth2/token',
        },
        f,
    )

  boto_path = os.path.join(tmpdir, 'mock.boto')
  with open(boto_path, 'w', encoding='utf-8') as f:
    f.write(
        '[Boto]\n'
        f'ca_certificates_file = {ca_pem}\n'
        'https_validate_certificates = False\n'
        'num_retries = 1\n'
        '[Credentials]\n'
        'use_client_certificate = False\n'
        'gs_host = 127.0.0.1\n'
        'gs_json_host = 127.0.0.1\n'
        f'gs_port = {port}\n'
        f'gs_json_port = {port}\n'
        '[GSUtil]\n'
        'prefer_api = json\n'
        f'default_project_id = {project_id}\n'
        f'state_dir = {state_dir}\n'
    )

  os.environ['BOTO_CONFIG'] = boto_path
  os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = adc_path
  os.environ['SSL_CERT_FILE'] = ca_pem
  os.environ['REQUESTS_CA_BUNDLE'] = ca_pem
  os.environ['CLOUDSDK_CORE_PASS_CREDENTIALS_TO_GSUTIL'] = 'False'
  os.environ['CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE'] = 'false'
  os.environ['HOME'] = fake_home
  os.environ['CLOUDSDK_CONFIG'] = fake_home
  os.environ.pop('GSUTIL_NO_BANNER', None)
  os.environ['LC_ALL'] = 'C.UTF-8'
  os.environ['TZ'] = 'UTC'

  def cleanup():
    if proc.poll() is None:
      proc.terminate()
      try:
        proc.wait(timeout=5)
      except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(tmpdir, ignore_errors=True)

  return {'port': port, 'tmpdir': tmpdir, 'boto': boto_path}, cleanup


def _mint_gcloud_token(token_file):
  now = time.time()
  if token_file and os.path.exists(token_file):
    try:
      with open(token_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
      if data.get('token') and (now - data.get('fetched_at', 0)) < 2400:
        return data['token']
    except Exception:
      pass
  tok = subprocess.check_output(
      ['gcloud', 'auth', 'print-access-token'], text=True, timeout=30
  ).strip()
  if token_file:
    tmp = f'{token_file}.{os.getpid()}.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
      json.dump({'token': tok, 'fetched_at': now}, f)
    os.replace(tmp, token_file)
  return tok


def _start_live_backend(project_id):
  tmpdir = tempfile.mkdtemp(prefix='gsutil-rs-upstream-live-')
  state_dir = os.path.join(tmpdir, 'state')
  os.makedirs(state_dir, exist_ok=True)
  token_file = os.path.join(tmpdir, 'live_token.json')
  _mint_gcloud_token(token_file)

  proxy_proc = None
  ecp_bin = '/usr/bin/ecp_http_proxy'
  ecp_cfg = '/etc/gcloud/certificate_config.json'
  proxy_port = None
  ecp_disabled = (
      os.environ.get('CLOUDSDK_CONTEXT_AWARE_USE_ECP_HTTP_PROXY', '').lower() == 'false'
      or os.environ.get('CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE', '').lower() == 'false'
  )
  if ecp_disabled:
    os.environ.pop('GSUTIL_ECP_PROXY_PORT', None)
  elif os.path.exists(ecp_bin) and os.path.exists(ecp_cfg):
    proxy_port = _pick_free_port()
    proxy_proc = subprocess.Popen(
        [
            ecp_bin,
            '-port',
            str(proxy_port),
            '-enterprise_certificate_file_path',
            ecp_cfg,
            '-nonce_token',
            'gsutil-rs-live',
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ready = False
    for _ in range(100):
      try:
        with urllib.request.urlopen(
            f'http://127.0.0.1:{proxy_port}/readyz', timeout=0.5
        ) as resp:
          if resp.status == 200:
            ready = True
            break
      except Exception:
        time.sleep(0.1)
    if not ready:
      proxy_proc.terminate()
      shutil.rmtree(tmpdir, ignore_errors=True)
      raise RuntimeError(f'ecp_http_proxy on port {proxy_port} never became ready')
    os.environ['GSUTIL_ECP_PROXY_PORT'] = str(proxy_port)

  boto_path = os.path.join(tmpdir, 'live.boto')
  with open(boto_path, 'w', encoding='utf-8') as f:
    f.write(
        '[GSUtil]\n'
        'prefer_api = json\n'
        'use_gcloud_storage = False\n'
        f'default_project_id = {project_id}\n'
        f'state_dir = {state_dir}\n'
    )

  os.environ.pop('BOTO_PATH', None)
  os.environ['BOTO_CONFIG'] = boto_path
  os.environ['GSUTIL_LIVE_TOKEN_FILE'] = token_file
  os.environ['CLOUDSDK_CORE_PROJECT'] = project_id
  os.environ.pop('GSUTIL_NO_BANNER', None)
  os.environ['LC_ALL'] = 'C.UTF-8'
  os.environ['TZ'] = 'UTC'

  def cleanup():
    if proxy_proc is not None and proxy_proc.poll() is None:
      proxy_proc.terminate()
      try:
        proxy_proc.wait(timeout=5)
      except subprocess.TimeoutExpired:
        proxy_proc.kill()
    shutil.rmtree(tmpdir, ignore_errors=True)

  return {
      'proxy_port': proxy_port,
      'tmpdir': tmpdir,
      'boto': boto_path,
      'token_file': token_file,
  }, cleanup


def _install_live_ecp_transport_patches():
  """Route Python test harness HTTP clients (httplib2 + boto GSConnection) with gcloud bearer auth.

  When GSUTIL_ECP_PROXY_PORT is set (Context-Aware Access), routes via local ecp_http_proxy mTLS.
  When unset (personal GCP / direct HTTPS), sends directly over HTTPS with gcloud bearer auth.
  """
  ecp_port_str = os.environ.get('GSUTIL_ECP_PROXY_PORT', '').strip()
  ecp_port = int(ecp_port_str) if ecp_port_str else None
  token_file = os.environ.get('GSUTIL_LIVE_TOKEN_FILE', '')

  import httplib2
  import boto.gs.connection
  import boto.s3.connection

  orig_httplib2_request = httplib2.Http.request
  mtls_re = re.compile(
      r'^(storage|www|cloudkms|pubsub|iamcredentials)(\.mtls)?\.googleapis\.com(?::\d+)?$'
  )

  def _ecp_httplib2_request(
      self,
      uri,
      method='GET',
      body=None,
      headers=None,
      redirections=httplib2.DEFAULT_MAX_REDIRECTS,
      connection_type=None,
  ):
    parsed = urllib.parse.urlsplit(uri)
    m = mtls_re.match(parsed.netloc.lower())
    if m:
      svc = m.group(1)
      mtls_host = 'storage.mtls.googleapis.com' if svc == 'www' else f'{svc}.mtls.googleapis.com'
      q_pairs = [
          (k, v)
          for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
          if k != 'key'
      ]
      new_query = urllib.parse.urlencode(q_pairs)
      new_headers = {}
      if headers:
        for k, v in headers.items():
          ks = k.decode('latin-1') if isinstance(k, bytes) else str(k)
          if ks.lower() in ('authorization', 'host', 'x-goog-ecpproxy-target-host'):
            continue
          vs = v.decode('latin-1') if isinstance(v, bytes) else str(v)
          new_headers[ks] = vs
      tok = _mint_gcloud_token(token_file)
      new_headers['Authorization'] = f'Bearer {tok}'
      if ecp_port is not None:
        new_uri = urllib.parse.urlunsplit((
            'http',
            f'127.0.0.1:{ecp_port}',
            parsed.path,
            new_query,
            parsed.fragment,
        ))
        new_headers['x-goog-ecpproxy-target-host'] = mtls_host
        return orig_httplib2_request(
            self,
            new_uri,
            method=method,
            body=body,
            headers=new_headers,
            redirections=redirections,
            connection_type=None,
        )
      new_uri = urllib.parse.urlunsplit((
          parsed.scheme or 'https',
          parsed.netloc,
          parsed.path,
          new_query,
          parsed.fragment,
      ))
      return orig_httplib2_request(
          self,
          new_uri,
          method=method,
          body=body,
          headers=new_headers,
          redirections=redirections,
          connection_type=connection_type,
      )
    return orig_httplib2_request(
        self,
        uri,
        method=method,
        body=body,
        headers=headers,
        redirections=redirections,
        connection_type=connection_type,
    )

  httplib2.Http.request = _ecp_httplib2_request

  orig_gs_init = boto.gs.connection.GSConnection.__init__
  orig_gs_make_request = boto.gs.connection.GSConnection.make_request

  def _ecp_gs_init(self, *args, **kwargs):
    if ecp_port is not None:
      kwargs['is_secure'] = False
      kwargs['host'] = '127.0.0.1'
      kwargs['port'] = ecp_port
      kwargs['calling_format'] = boto.s3.connection.OrdinaryCallingFormat()
    orig_gs_init(self, *args, **kwargs)

  def _ecp_gs_make_request(self, method, bucket='', key='', headers=None, *args, **kwargs):
    new_headers = dict(headers) if headers else {}
    for k in list(new_headers.keys()):
      if k.lower() in ('authorization', 'x-goog-ecpproxy-target-host'):
        del new_headers[k]
    tok = _mint_gcloud_token(token_file)
    new_headers['Authorization'] = f'Bearer {tok}'
    if ecp_port is not None:
      new_headers['x-goog-ecpproxy-target-host'] = 'storage.mtls.googleapis.com'
    return orig_gs_make_request(
        self, method, bucket=bucket, key=key, headers=new_headers, *args, **kwargs
    )

  boto.gs.connection.GSConnection.__init__ = _ecp_gs_init
  boto.gs.connection.GSConnection.make_request = _ecp_gs_make_request


def _install_gslib_and_monkeypatch(
    rust_bin, cmd_timeout_s, is_mock=False, live_boto_path=None
):
  if GSUTIL_DIR not in sys.path:
    sys.path.insert(0, GSUTIL_DIR)

  # Importing gsutil bootstraps all bundled third_party libraries (boto, apitools, httplib2, etc.).
  saved_argv = sys.argv[:]
  sys.argv = ['gsutil']
  try:
    import gsutil as _gsutil_bootstrap  # noqa: F401
    import gslib.__main__ as _gslib_main  # noqa: F401
  finally:
    sys.argv = saved_argv
  from gslib.project_id import PopulateProjectId
  import gslib.tests.testcase.integration_testcase as integration_testcase
  import gslib.tests.util as test_util

  if not is_mock:
    _install_live_ecp_transport_patches()

  test_util.RUN_INTEGRATION_TESTS = True
  test_util.RUN_UNIT_TESTS = False
  test_util.RUN_S3_TESTS = False
  test_util.USING_JSON_API = True

  def _build_rust_cmd(raw_command, force_gsutil=False):
    del force_gsutil
    cmd = [rust_bin]
    if is_mock:
      # Rust reqwest verifies 127.0.0.1 IP SAN against mock_ca.pem cleanly;
      # keep https_validate_certificates=True for Rust so it doesn't emit the
      # insecure-TLS warning banner to stderr on every command.
      cmd.extend(['-o', 'Boto:https_validate_certificates=True'])
    try:
      proj = PopulateProjectId()
    except Exception:
      proj = None
    if proj:
      cmd.extend(['-o', f'GSUtil:default_project_id={proj}'])
    cmd.extend(str(part) for part in raw_command)
    return cmd

  test_util.GetGsutilCommand = _build_rust_cmd

  def _patched_run_gsutil(
      self,
      cmd,
      return_status=False,
      return_stdout=False,
      return_stderr=False,
      expected_status=0,
      stdin=None,
      env_vars=None,
      force_gsutil=False,
  ):
    full_cmd = _build_rust_cmd(cmd, force_gsutil=force_gsutil)
    env = os.environ.copy()
    if live_boto_path and not env.get('BOTO_CONFIG'):
      # Let Rust gsutil use gcloud auth + GSUTIL_ECP_PROXY_PORT rather than
      # Python's legacy_credentials/.boto refresh token.
      env.pop('BOTO_PATH', None)
      env['BOTO_CONFIG'] = live_boto_path
    if env_vars:
      for k, v in env_vars.items():
        if v is None:
          env.pop(k, None)
        else:
          env[str(k)] = str(v)

    stdin_bytes = None
    if stdin is not None:
      stdin_bytes = stdin if isinstance(stdin, bytes) else str(stdin).encode('utf-8')

    proc = subprocess.Popen(
        full_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        env=env,
        preexec_fn=os.setsid,
    )
    try:
      raw_out, raw_err = proc.communicate(input=stdin_bytes, timeout=cmd_timeout_s)
    except subprocess.TimeoutExpired:
      try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
      except OSError:
        proc.kill()
      raw_out, raw_err = proc.communicate()
      raise AssertionError(
          f'Rust gsutil timed out after {cmd_timeout_s}s.\n'
          f'Command: {" ".join(full_cmd)}\n'
          f'stderr:\n{raw_err.decode("utf-8", errors="replace")}'
      )

    stdout = raw_out.decode('utf-8', errors='replace').replace(os.linesep, '\n')
    stderr = raw_err.decode('utf-8', errors='replace').replace(os.linesep, '\n')
    status = proc.returncode

    if expected_status is not None:
      self.assertEqual(
          int(status),
          int(expected_status),
          msg=(
              f'Expected status {expected_status}, got {status}.\n'
              f'Command:\n{" ".join(str(c) for c in cmd)}\n\n'
              f'stderr:\n{stderr}\n\nstdout:\n{stdout[:500]}'
          ),
      )

    toreturn = []
    if return_status:
      toreturn.append(status)
    if return_stdout:
      toreturn.append(stdout)
    if return_stderr:
      toreturn.append(stderr)

    if len(toreturn) == 1:
      return toreturn[0]
    if toreturn:
      return tuple(toreturn)
    return None

  integration_testcase.GsUtilIntegrationTestCase.RunGsUtil = _patched_run_gsutil
  return integration_testcase.GsUtilIntegrationTestCase


def _discover_all_test_modules():
  tests_dir = os.path.join(GSUTIL_DIR, 'gslib', 'tests')
  mods = []
  for entry in sorted(os.listdir(tests_dir)):
    if entry.startswith('test_') and entry.endswith('.py'):
      mods.append(entry[:-3])
  return mods


def _extract_failure_signature(tb_text):
  lines = [l.strip() for l in tb_text.strip().splitlines() if l.strip()]
  if not lines:
    return 'Unknown failure'
  # Look for Expected status X, got Y + first CommandException/Error line
  for idx, line in enumerate(lines):
    m = re.search(r'Expected status (\d+), got (\d+)', line)
    if m:
      err_hint = ''
      for sub in lines[idx + 1 :]:
        if any(
            tok in sub
            for tok in (
                'CommandException:',
                'ServiceException:',
                'NotFoundException:',
                'AccessDeniedException:',
                'PreconditionException:',
                'Error:',
                'error:',
                'unknown flag',
                'Unknown option',
                'unrecognized',
            )
        ):
          err_hint = re.sub(r'gs://[^\s\'"]+', 'gs://<bucket>/<obj>', sub)[:120]
          break
      return f'Exit {m.group(2)} (expected {m.group(1)}): {err_hint or "no stderr"}'
  last = lines[-1]
  last = re.sub(r'gs://[^\s\'"]+', 'gs://<bucket>/<obj>', last)
  last = re.sub(r'/tmp/[^\s\'"]+', '/tmp/<path>', last)
  return last[:140]


class _TestTimeoutError(Exception):
  pass


class StructuredResult(unittest.TestResult):

  def __init__(self, test_timeout_s=45, stream_path=None):
    super().__init__()
    self.records = []
    self._starts = {}
    self._test_timeout_s = test_timeout_s
    self._stream_path = stream_path

  def _emit(self, rec):
    self.records.append(rec)
    if self._stream_path:
      with open(self._stream_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(rec) + '\n')

  def startTest(self, test):
    super().startTest(test)
    self._starts[test.id()] = time.monotonic()
    if self._test_timeout_s > 0:
      def _alarm_handler(signum, frame):
        del signum, frame
        raise _TestTimeoutError(f'Test exceeded {self._test_timeout_s}s wall-clock timeout')
      signal.signal(signal.SIGALRM, _alarm_handler)
      signal.alarm(self._test_timeout_s)

  def stopTest(self, test):
    if self._test_timeout_s > 0:
      signal.alarm(0)
    super().stopTest(test)

  def _elapsed(self, test):
    return round(time.monotonic() - self._starts.get(test.id(), time.monotonic()), 3)

  def addSuccess(self, test):
    super().addSuccess(test)
    self._emit({
        'id': test.id(),
        'status': 'PASS',
        'duration_s': self._elapsed(test),
    })

  def addFailure(self, test, err):
    super().addFailure(test, err)
    tb_text = ''.join(traceback.format_exception(*err))
    self._emit({
        'id': test.id(),
        'status': 'FAIL',
        'duration_s': self._elapsed(test),
        'signature': _extract_failure_signature(tb_text),
        'traceback': '\n'.join(tb_text.splitlines()[-25:]),
    })

  def addError(self, test, err):
    super().addError(test, err)
    tb_text = ''.join(traceback.format_exception(*err))
    self._emit({
        'id': test.id(),
        'status': 'ERROR',
        'duration_s': self._elapsed(test),
        'signature': _extract_failure_signature(tb_text),
        'traceback': '\n'.join(tb_text.splitlines()[-25:]),
    })

  def addSkip(self, test, reason):
    super().addSkip(test, reason)
    self._emit({
        'id': test.id(),
        'status': 'SKIP',
        'duration_s': self._elapsed(test),
        'reason': str(reason),
    })


def _iter_tests(suite):
  for item in suite:
    if isinstance(item, unittest.TestSuite):
      yield from _iter_tests(item)
    else:
      yield item


def _render_markdown(report):
  s = report['summary']
  lines = [
      f'# Upstream `gslib/tests/` Black-Box Report ({report["backend"]})',
      '',
      f'- **Generated**: {report["timestamp"]}',
      f'- **Rust binary**: `{report["rust_bin"]}`',
      f'- **Modules requested**: {s["modules_requested"]} (imported: {s["modules_imported"]}, missing/import-error: {s["modules_import_errors"]})',
      f'- **Tests run**: {s["total"]} | **PASS**: {s["passed"]} | **FAIL**: {s["failed"]} | **ERROR**: {s["errored"]} | **SKIP**: {s["skipped"]}',
      f'- **Pass rate (excluding skips)**: {s["pass_rate_non_skipped"]:.1f}% ({s["passed"]}/{s["passed"] + s["failed"] + s["errored"]})',
      f'- **Elapsed**: {s["duration_s"]:.1f}s',
      '',
      '## Per-Module Breakdown',
      '',
      '| Module | Total | Pass | Fail | Error | Skip | Pass% (non-skip) | Time (s) |',
      '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ]
  for mod in report['modules']:
    ns = mod['passed'] + mod['failed'] + mod['errored']
    pct = (100.0 * mod['passed'] / ns) if ns else 100.0
    lines.append(
        f'| `{mod["name"]}` | {mod["total"]} | {mod["passed"]} | {mod["failed"]} | '
        f'{mod["errored"]} | {mod["skipped"]} | {pct:.1f}% | {mod["duration_s"]:.1f} |'
    )

  if report['grouped_failures']:
    lines.extend([
        '',
        '## Top Grouped Failure / Error Root Causes',
        '',
        '| Count | Modules | Root-Cause Signature | Example Test |',
        '| ---: | --- | --- | --- |',
    ])
    for grp in report['grouped_failures'][:40]:
      mods_str = ', '.join(grp['modules'][:4])
      if len(grp['modules']) > 4:
        mods_str += f' (+{len(grp["modules"]) - 4})'
      sig = grp['signature'].replace('|', '\\|')
      lines.append(
          f'| {grp["count"]} | {mods_str} | `{sig}` | `{grp["example_test"]}` |'
      )

  return '\n'.join(lines) + '\n'


def main():
  parser = argparse.ArgumentParser(
      description='Run official upstream Python gsutil integration tests against Rust gsutil.'
  )
  parser.add_argument('--backend', choices=['mock', 'live'], default='mock')
  parser.add_argument('--modules', default='', help='Comma-separated test module names')
  parser.add_argument('--all', action='store_true', help='Run all gslib/tests/test_*.py modules')
  parser.add_argument('--rust-bin', default=DEFAULT_RUST_BIN)
  parser.add_argument('--parity-bin', default=DEFAULT_PARITY_BIN)
  parser.add_argument('--project', default='')
  parser.add_argument('--timeout', type=int, default=0, help='Per-command timeout in seconds')
  parser.add_argument('--test-timeout', type=int, default=0, help='Per-test wall-clock timeout in seconds')
  parser.add_argument('--module-timeout', type=int, default=0, help='Per-module wall-clock timeout in seconds')
  parser.add_argument('--jobs', type=int, default=0, help='Parallel module workers (default 4 mock, 1 live)')
  parser.add_argument('--filter', default='', help='Substring filter on test ID')
  parser.add_argument('--out-dir', default='', help='Directory to write JSON & Markdown reports')
  parser.add_argument('--_worker-module', default='', help=argparse.SUPPRESS)
  parser.add_argument('--_worker-out', default='', help=argparse.SUPPRESS)
  parser.add_argument('--_live-boto', default='', help=argparse.SUPPRESS)
  args = parser.parse_args()

  if not os.path.exists(args.rust_bin):
    sys.exit(f'Rust binary not found: {args.rust_bin}')

  project_id = args.project or os.environ.get('GSUTIL_TEST_PROJECT') or (
      'mock-project-123' if args.backend == 'mock' else ''
  )
  if args.backend == 'live' and not project_id:
    sys.exit('Live backend requires --project <GCP_PROJECT_ID> or GSUTIL_TEST_PROJECT')
  cmd_timeout = args.timeout or (20 if args.backend == 'mock' else 120)
  test_timeout = args.test_timeout or (25 if args.backend == 'mock' else 150)
  module_timeout = args.module_timeout or (150 if args.backend == 'mock' else 300)
  jobs = args.jobs or (4 if args.backend == 'mock' else 1)

  if args._worker_module:
    integration_base = _install_gslib_and_monkeypatch(
        args.rust_bin,
        cmd_timeout,
        is_mock=(args.backend == 'mock'),
        live_boto_path=(args._live_boto or None),
    )
    loader = unittest.TestLoader()
    full_mod = f'gslib.tests.{args._worker_module}'
    try:
      mod = importlib.import_module(full_mod)
    except Exception as exc:
      with open(args._worker_out, 'w', encoding='utf-8') as f:
        f.write(json.dumps({'_import_error': str(exc)}) + '\n')
      return
    suite = unittest.TestSuite()
    for test_case in _iter_tests(loader.loadTestsFromModule(mod)):
      if not isinstance(test_case, integration_base):
        continue
      if args.filter and args.filter not in test_case.id():
        continue
      suite.addTest(test_case)
    res = StructuredResult(test_timeout_s=test_timeout, stream_path=args._worker_out)
    suite.run(res)
    return

  if args.all:
    module_names = _discover_all_test_modules()
  elif args.modules:
    module_names = [m.strip() for m in args.modules.split(',') if m.strip()]
  else:
    module_names = list(DEFAULT_STAGE2_MODULES)

  if args.backend == 'mock':
    backend_info, cleanup = _start_mock_backend(args.parity_bin, project_id)
  else:
    backend_info, cleanup = _start_live_backend(project_id)

  t_start = time.monotonic()
  module_reports = []
  import_errors = []
  all_records = []
  worker_tmp = os.path.join(backend_info['tmpdir'], 'worker_results')
  os.makedirs(worker_tmp, exist_ok=True)

  def _run_module_subprocess(mod_name):
    out_jsonl = os.path.join(worker_tmp, f'{mod_name}.jsonl')
    m_start = time.monotonic()
    cmd = [
        sys.executable,
        os.path.abspath(__file__),
        '--backend',
        args.backend,
        '--rust-bin',
        args.rust_bin,
        '--project',
        project_id,
        '--timeout',
        str(cmd_timeout),
        '--test-timeout',
        str(test_timeout),
        '--_worker-module',
        mod_name,
        '--_worker-out',
        out_jsonl,
    ]
    if args.filter:
      cmd.extend(['--filter', args.filter])
    if args.backend == 'live':
      cmd.extend(['--_live-boto', backend_info['boto']])

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
    )
    timed_out = False
    try:
      proc.communicate(timeout=module_timeout)
    except subprocess.TimeoutExpired:
      timed_out = True
      try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
      except OSError:
        proc.kill()
      proc.communicate()

    m_dur = round(time.monotonic() - m_start, 2)
    records = []
    if os.path.exists(out_jsonl):
      with open(out_jsonl, 'r', encoding='utf-8') as f:
        for line in f:
          line = line.strip()
          if not line:
            continue
          rec = json.loads(line)
          if '_import_error' in rec:
            return mod_name, None, rec['_import_error']
          records.append(rec)

    if timed_out:
      records.append({
          'id': f'gslib.tests.{mod_name}.<module_timeout>',
          'status': 'ERROR',
          'duration_s': m_dur,
          'signature': f'Module timed out after {module_timeout}s (likely hung FIFO or retry loop)',
          'traceback': f'Module {mod_name} exceeded {module_timeout}s wall-clock timeout after {len(records)} completed tests.',
      })

    counts = collections.Counter(r['status'] for r in records)
    mod_entry = {
        'name': mod_name,
        'total': len(records),
        'passed': counts['PASS'],
        'failed': counts['FAIL'],
        'errored': counts['ERROR'],
        'skipped': counts['SKIP'],
        'duration_s': m_dur,
        'records': records,
    }
    return mod_name, mod_entry, None

  try:
    results_by_mod = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
      futs = {pool.submit(_run_module_subprocess, m): m for m in module_names}
      for fut in concurrent.futures.as_completed(futs):
        mod_name, mod_entry, imp_err = fut.result()
        if imp_err is not None:
          import_errors.append({'module': mod_name, 'error': imp_err})
          print(f'[IMPORT-ERR] {mod_name}: {imp_err}', flush=True)
        else:
          results_by_mod[mod_name] = mod_entry
          print(
              f'[{mod_name}] total={mod_entry["total"]} pass={mod_entry["passed"]} '
              f'fail={mod_entry["failed"]} err={mod_entry["errored"]} '
              f'skip={mod_entry["skipped"]} ({mod_entry["duration_s"]:.1f}s)',
              flush=True,
          )
    for m in module_names:
      if m in results_by_mod:
        module_reports.append(results_by_mod[m])
        all_records.extend(results_by_mod[m]['records'])
  finally:
    cleanup()

  total_dur = round(time.monotonic() - t_start, 2)
  totals = collections.Counter(r['status'] for r in all_records)
  non_skip = totals['PASS'] + totals['FAIL'] + totals['ERROR']
  pass_rate = (100.0 * totals['PASS'] / non_skip) if non_skip else 100.0

  sig_groups = {}
  for mod_entry in module_reports:
    for rec in mod_entry['records']:
      if rec['status'] in ('FAIL', 'ERROR'):
        sig = rec.get('signature', 'Unknown')
        g = sig_groups.setdefault(
            sig,
            {
                'signature': sig,
                'count': 0,
                'modules': set(),
                'example_test': rec['id'],
                'example_traceback': rec.get('traceback', ''),
            },
        )
        g['count'] += 1
        g['modules'].add(mod_entry['name'])

  grouped_failures = sorted(
      (
          {
              'signature': g['signature'],
              'count': g['count'],
              'modules': sorted(g['modules']),
              'example_test': g['example_test'],
              'example_traceback': g['example_traceback'],
          }
          for g in sig_groups.values()
      ),
      key=lambda x: (-x['count'], x['signature']),
  )

  report = {
      'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
      'backend': args.backend,
      'rust_bin': args.rust_bin,
      'project_id': project_id,
      'backend_info': {k: str(v) for k, v in backend_info.items()},
      'summary': {
          'modules_requested': len(module_names),
          'modules_imported': len(module_reports),
          'modules_import_errors': len(import_errors),
          'total': len(all_records),
          'passed': totals['PASS'],
          'failed': totals['FAIL'],
          'errored': totals['ERROR'],
          'skipped': totals['SKIP'],
          'pass_rate_non_skipped': round(pass_rate, 2),
          'duration_s': total_dur,
      },
      'import_errors': import_errors,
      'modules': module_reports,
      'grouped_failures': grouped_failures,
  }

  md = _render_markdown(report)
  if args.out_dir:
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, 'upstream_report.json'), 'w', encoding='utf-8') as f:
      json.dump(report, f, indent=2)
    with open(os.path.join(args.out_dir, 'upstream_report.md'), 'w', encoding='utf-8') as f:
      f.write(md)

  print('\n' + md, flush=True)
  if totals['FAIL'] > 0 or totals['ERROR'] > 0:
    sys.exit(1)


if __name__ == '__main__':
  main()
