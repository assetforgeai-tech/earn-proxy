import sys, pathlib, sqlite3
import pytest
sys.path.insert(0,str(pathlib.Path(__file__).parents[1]))
from app import app, parse_proxy_line, format_endpoint, format_raw_proxy, duplicate_raw_csv, selected_ids, unique_exit_rows, client_port, job_snapshot
from app import should_commit_check_results, job_should_stop, result_counts, active_job_id, terminal_job, apply_check_result, FAILURE_THRESHOLD
from app import proxy_counts, build_proxy_filters, pagination_window, sync_proxiware_bindings
from app import web_bind

def test_web_bind_defaults_to_loopback_internal_port(monkeypatch):
    monkeypatch.delenv('RELAY_WEB_HOST', raising=False)
    monkeypatch.delenv('RELAY_WEB_PORT', raising=False)
    assert web_bind() == ('127.0.0.1', 8000)


def test_relay_sso_token_is_signed_and_expires(monkeypatch):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'RELAY_SSO_SECRET', 'test-secret')
    token=relay_app.issue_sso_token()
    assert relay_app.verify_sso_token(token)
    assert not relay_app.verify_sso_token(token + 'tampered')


def test_internal_feed_requires_loopback_key_and_returns_fixed_endpoints(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    monkeypatch.setattr(relay_app, 'RELAY_FEED_KEY', 'feed-secret')
    c=relay_app.conn()
    c.execute("insert into proxies(host,port,username,password,protocol,status,detected_protocol,exit_ip,http_port,socks_port) values(?,?,?,?,?,?,?,?,?,?)", ('upstream', 8080, 'u', 'p', 'auto', 'live', 'socks5', '198.51.100.5', 20001, 30001))
    c.commit(); c.close()
    with relay_app.app.test_client() as client:
        denied=client.get('/internal/feed', headers={'X-Relay-Feed-Key':'feed-secret'}, environ_base={'REMOTE_ADDR':'192.0.2.10'})
        allowed=client.get('/internal/feed', headers={'X-Relay-Feed-Key':'feed-secret'}, environ_base={'REMOTE_ADDR':'127.0.0.1'})
    assert denied.status_code in (401, 403)
    assert allowed.status_code == 200
    assert allowed.get_json()['items'][0]['proxy'].startswith('42.96.12.142:30001:client:')


def test_proxiware_binding_sync_creates_once_then_updates_same_listener(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    c = relay_app.conn()
    slot = 'pw1_' + 'a' * 64
    first = {'slot_key': slot, 'raw': 'first.proxy.example:9000:user:pass', 'protocol': 'socks5', 'live_status': 'live', 'qualification': 'allow', 'exit_ip': '198.51.100.10'}
    created = sync_proxiware_bindings(c, [first], reload=False)
    original = c.execute('select * from proxies where provider_slot_key=?', (slot,)).fetchone()
    changed = {'slot_key': slot, 'raw': 'second.proxy.example:9001:user2:pass2', 'protocol': 'http', 'live_status': 'live', 'qualification': 'risk', 'exit_ip': '198.51.100.11'}
    updated = sync_proxiware_bindings(c, [changed], reload=False)
    current = c.execute('select * from proxies where provider_slot_key=?', (slot,)).fetchone()

    assert created['created'] == 1
    assert updated['updated'] == 1
    assert current['id'] == original['id']
    assert (current['http_port'], current['socks_port']) == (original['http_port'], original['socks_port'])
    assert current['listener_port'] == original['socks_port']
    assert relay_app.client_port(current) == original['socks_port']
    assert current['detected_protocol'] == 'http'
    assert relay_app.format_endpoint(current, 'http', '42.96.12.142', 'client', 'secret') == f"42.96.12.142:{original['socks_port']}:client:secret"
    assert (current['host'], current['port'], current['username'], current['password']) == ('second.proxy.example', 9001, 'user2', 'pass2')
    assert c.execute('select count(*) from proxies where provider_slot_key=?', (slot,)).fetchone()[0] == 1
    c.close()


def test_proxiware_provider_live_metadata_does_not_mark_transfer_online(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    c = relay_app.conn()
    slot = 'pw1_' + 'c' * 64
    sync_proxiware_bindings(c, [{'slot_key': slot, 'raw': 'proxy.example:9000:user:pass', 'protocol': 'socks5', 'live_status': 'live'}], reload=False)

    row = c.execute('select status,last_check_status,exit_ip from proxies where provider_slot_key=?', (slot,)).fetchone()
    assert tuple(row) == ('unknown', 'unknown', '')
    c.close()


def test_proxiware_upstream_change_invalidates_online_check_but_keeps_listener_ports(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    c = relay_app.conn()
    slot = 'pw1_' + 'd' * 64
    sync_proxiware_bindings(c, [{'slot_key': slot, 'raw': 'old.proxy.example:9000:user:pass', 'protocol': 'socks5', 'live_status': 'live'}], reload=False)
    c.execute("update proxies set status='live',last_check_status='live',exit_ip='203.0.113.8',checked_at=current_timestamp where provider_slot_key=?", (slot,))
    original = c.execute('select id,http_port,socks_port from proxies where provider_slot_key=?', (slot,)).fetchone()

    sync_proxiware_bindings(c, [{'slot_key': slot, 'raw': 'new.proxy.example:9001:user2:pass2', 'protocol': 'socks5', 'live_status': 'live'}], reload=False)

    current = c.execute('select id,http_port,socks_port,status,last_check_status,exit_ip,checked_at from proxies where provider_slot_key=?', (slot,)).fetchone()
    assert tuple(current[:3]) == tuple(original)
    assert tuple(current[3:]) == ('unknown', 'unknown', '', None)
    c.close()


def test_legacy_live_rows_are_reset_once_for_end_to_end_migration(monkeypatch, tmp_path):
    import sqlite3
    import app as relay_app

    db_path = tmp_path / 'relay.db'
    legacy = sqlite3.connect(db_path)
    legacy.execute('''create table proxies(
        id integer primary key,host text not null,port integer not null,username text,password text,
        protocol text default 'auto',status text default 'unknown',detected_protocol text,exit_ip text,
        latency_ms integer,error text,http_port integer unique,socks_port integer unique,enabled integer default 1,
        created_at text default current_timestamp,checked_at text,import_batch_id integer,last_check_status text,
        failure_streak integer not null default 0,provider_slot_key text)''')
    legacy.execute("insert into proxies(host,port,status,detected_protocol,exit_ip,http_port,socks_port,last_check_status) values('old.example',1080,'live','socks5','203.0.113.80',20080,30080,'live')")
    legacy.commit()
    legacy.close()
    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(db_path))

    c = relay_app.conn()
    row = c.execute('select status,last_check_status,exit_ip,checked_at,transfer_checked_at from proxies').fetchone()
    assert tuple(row) == ('unknown', 'unknown', '', None, None)
    c.execute("update proxies set status='live',transfer_checked_at=current_timestamp where id=1")
    c.commit()
    c.close()

    c = relay_app.conn()
    assert c.execute('select status from proxies where id=1').fetchone()['status'] == 'live'
    c.close()


def test_proxiware_swap_keeps_listener_during_pending_protocol_recheck(monkeypatch, tmp_path):
    import json
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    monkeypatch.setattr(relay_app.subprocess, 'run', lambda *_args, **_kwargs: None)
    c = relay_app.conn()
    slot = 'pw1_' + '9' * 64
    dead_slot = 'pw1_' + '8' * 64
    dead = {'slot_key': dead_slot, 'raw': 'dead.proxy.example:9002:user:pass', 'protocol': 'socks5', 'live_status': 'dead'}
    sync_proxiware_bindings(
        c,
        [
            {'slot_key': slot, 'raw': 'old.proxy.example:9000:user:pass', 'protocol': 'socks5', 'live_status': 'live'},
            dead,
        ],
        reload=False,
    )
    original = c.execute('select id,http_port,socks_port from proxies where provider_slot_key=?', (slot,)).fetchone()

    sync_proxiware_bindings(
        c,
        [
            {'slot_key': slot, 'raw': 'new.proxy.example:9001:user2:pass2', 'protocol': 'auto', 'live_status': 'pending'},
            dead,
        ],
        reload=False,
    )
    current = c.execute('select * from proxies where provider_slot_key=?', (slot,)).fetchone()
    dead_status = c.execute('select status from proxies where provider_slot_key=?', (dead_slot,)).fetchone()['status']
    c.close()
    relay_app.reload_relay()
    runtime = json.loads((tmp_path / 'relay.json').read_text())

    assert (current['id'], current['http_port'], current['socks_port']) == tuple(original)
    assert current['detected_protocol'] == 'socks5'
    assert [(entry['host'], entry['protocol'], entry['port']) for entry in runtime['entries']] == [
        ('new.proxy.example', 'socks5', original['socks_port']),
    ]
    assert dead_status == 'dead'


def test_fifty_proxiware_slots_keep_their_transfer_rows_and_ports_after_swap(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    c = relay_app.conn()
    slots = [f'pw1_{index:064x}' for index in range(50)]
    before = [
        {'slot_key': slot, 'raw': f'old-{index}.proxy.example:9000:user:pass', 'protocol': 'socks5', 'live_status': 'live'}
        for index, slot in enumerate(slots)
    ]
    after = [
        {'slot_key': slot, 'raw': f'new-{index}.proxy.example:9100:user:pass', 'protocol': 'socks5', 'live_status': 'live'}
        for index, slot in enumerate(slots)
    ]

    assert sync_proxiware_bindings(c, before, reload=False)['created'] == 50
    original = {row['provider_slot_key']: (row['id'], row['http_port'], row['socks_port']) for row in c.execute('select * from proxies')}
    assert sync_proxiware_bindings(c, after, reload=False)['updated'] == 50
    current = {row['provider_slot_key']: (row['id'], row['http_port'], row['socks_port']) for row in c.execute('select * from proxies')}
    repeated = sync_proxiware_bindings(c, after, reload=False)

    assert len(current) == 50
    assert current == original
    assert repeated['changed'] is False
    assert c.execute("select count(*) from proxies where host like 'new-%'").fetchone()[0] == 50
    c.close()


def test_proxiware_binding_sync_adopts_one_exact_existing_transfer_proxy(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    c = relay_app.conn()
    c.execute('insert into proxies(host,port,username,password,http_port,socks_port) values(?,?,?,?,?,?)', ('raw.proxy.example', 9000, 'user', 'pass', 20123, 30123))
    c.commit()

    result = sync_proxiware_bindings(c, [{'slot_key': 'pw1_' + 'b' * 64, 'raw': 'raw.proxy.example:9000:user:pass', 'protocol': 'http', 'live_status': 'live'}], reload=False)
    row = c.execute('select * from proxies where provider_slot_key is not null').fetchone()

    assert result['adopted'] == 1
    assert (row['http_port'], row['socks_port']) == (20123, 30123)
    assert row['detected_protocol'] == 'http'
    c.close()


def test_proxiware_binding_sync_preserves_password_colons_from_structured_feed(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    c = relay_app.conn()

    sync_proxiware_bindings(c, [{'slot_key': 'pw1_' + 'f' * 64, 'upstream': {'host': 'colon.proxy.example', 'port': 9000, 'username': 'user', 'password': 'pass:with:colons'}, 'protocol': 'http', 'live_status': 'live'}], reload=False)
    row = c.execute('select * from proxies where provider_slot_key=?', ('pw1_' + 'f' * 64,)).fetchone()

    assert row['password'] == 'pass:with:colons'
    c.close()


def test_proxiware_binding_sync_rejects_ambiguous_or_duplicate_slots_without_partial_changes(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    c = relay_app.conn()
    for listener_offset in (0, 1):
        c.execute('insert into proxies(host,port,username,password,http_port,socks_port) values(?,?,?,?,?,?)', ('same.proxy.example', 9000, 'user', 'pass', 20000 + listener_offset, 30000 + listener_offset))
    c.commit()
    item = {'slot_key': 'pw1_' + 'c' * 64, 'raw': 'same.proxy.example:9000:user:pass', 'protocol': 'http', 'live_status': 'live'}

    with pytest.raises(ValueError, match='ambiguous'):
        sync_proxiware_bindings(c, [item], reload=False)
    with pytest.raises(ValueError, match='duplicate'):
        sync_proxiware_bindings(c, [item, item], reload=False)

    assert c.execute('select count(*) from proxies where provider_slot_key is not null').fetchone()[0] == 0
    c.close()


def test_proxiware_binding_sync_deactivates_absent_slots_without_deleting_their_identity(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    c = relay_app.conn()
    slot = 'pw1_' + 'd' * 64
    sync_proxiware_bindings(c, [{'slot_key': slot, 'raw': 'gone.proxy.example:9000:user:pass', 'protocol': 'http', 'live_status': 'live'}], reload=False)
    original = c.execute('select id,http_port,socks_port from proxies where provider_slot_key=?', (slot,)).fetchone()

    result = sync_proxiware_bindings(c, [], reload=False)
    inactive = c.execute('select * from proxies where provider_slot_key=?', (slot,)).fetchone()
    restored = sync_proxiware_bindings(c, [{'slot_key': slot, 'raw': 'gone.proxy.example:9000:user:pass', 'protocol': 'http', 'live_status': 'live'}], reload=False)
    active = c.execute('select * from proxies where provider_slot_key=?', (slot,)).fetchone()

    assert result['deactivated'] == 1
    assert inactive['enabled'] == 0
    assert (inactive['id'], inactive['http_port'], inactive['socks_port']) == tuple(original)
    assert restored['changed'] is True
    assert active['enabled'] == 1
    assert (active['id'], active['http_port'], active['socks_port']) == tuple(original)
    c.close()


def test_internal_proxiware_bindings_is_loopback_key_protected_and_no_store(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    monkeypatch.setattr(relay_app, 'RELAY_FEED_KEY', 'feed-secret')
    c = relay_app.conn()
    c.execute('insert into proxies(host,port,username,password,protocol,status,detected_protocol,exit_ip,http_port,socks_port,provider_slot_key) values(?,?,?,?,?,?,?,?,?,?,?)', ('raw.proxy.example', 9000, 'u', 'p', 'auto', 'live', 'socks5', '198.51.100.10', 20001, 30001, 'pw1_' + 'e' * 64))
    c.commit()
    c.close()
    with relay_app.app.test_client() as client:
        denied = client.get('/internal/proxiware-bindings', headers={'X-Relay-Feed-Key':'feed-secret'}, environ_base={'REMOTE_ADDR':'192.0.2.10'})
        allowed = client.get('/internal/proxiware-bindings', headers={'X-Relay-Feed-Key':'feed-secret'}, environ_base={'REMOTE_ADDR':'127.0.0.1'})

    assert denied.status_code == 401
    assert allowed.status_code == 200
    item = allowed.get_json()['items'][0]
    assert item['slot_key'] == 'pw1_' + 'e' * 64
    assert item['proxy'].startswith('42.96.12.142:30001:client:')
    assert 'username' not in item and 'password' not in item
    assert allowed.headers['Cache-Control'] == 'no-store'


def test_proxiware_binding_sync_timer_is_installed():
    from pathlib import Path

    root = Path(__file__).parents[1]
    unit = root / 'deploy' / 'proxy-relay-proxiware-sync.service'
    timer = root / 'deploy' / 'proxy-relay-proxiware-sync.timer'

    assert unit.exists() and timer.exists()
    assert 'proxy-relay-proxiware-sync.timer' in (root / 'deploy' / 'install.sh').read_text()


def test_proxiware_slot_sync_rejects_non_loopback_feed_url(monkeypatch):
    import sync_proxiware as relay_sync

    monkeypatch.setattr(relay_sync, 'PROXIWARE_SLOT_FEED_URL', 'http://example.com/feed')
    monkeypatch.setattr(relay_sync, 'RELAY_FEED_KEY', 'feed-secret')

    with pytest.raises(ValueError, match='target'):
        relay_sync.fetch_slots()


def test_proxiware_slot_sync_requires_complete_consistent_snapshot(monkeypatch):
    import json
    import sync_proxiware as relay_sync

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, limit):
            return json.dumps({'complete': False, 'count': 0, 'items': []}).encode()

    class Opener:
        def open(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(relay_sync, 'PROXIWARE_SLOT_FEED_URL', 'http://127.0.0.1:8100/internal/api/v1/proxiware-transfer-feed')
    monkeypatch.setattr(relay_sync, 'RELAY_FEED_KEY', 'feed-secret')
    monkeypatch.setattr(relay_sync, 'build_opener', lambda *_args: Opener())

    with pytest.raises(ValueError, match='incomplete'):
        relay_sync.fetch_slots()


def test_proxiware_slot_sync_rejects_oversized_feed(monkeypatch):
    import sync_proxiware as relay_sync

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, limit):
            return b'x' * limit

    class Opener:
        def open(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(relay_sync, 'PROXIWARE_SLOT_FEED_URL', 'http://127.0.0.1:8100/internal/api/v1/proxiware-transfer-feed')
    monkeypatch.setattr(relay_sync, 'RELAY_FEED_KEY', 'feed-secret')
    monkeypatch.setattr(relay_sync, 'MAX_FEED_BYTES', 10)
    monkeypatch.setattr(relay_sync, 'build_opener', lambda *_args: Opener())

    with pytest.raises(ValueError, match='too large'):
        relay_sync.fetch_slots()


def test_proxiware_slot_sync_propagates_feed_failure_without_running_database_sync(monkeypatch):
    from urllib.error import URLError
    import sync_proxiware as relay_sync

    class Opener:
        def open(self, *_args, **_kwargs):
            raise URLError('provider feed unavailable')

    monkeypatch.setattr(relay_sync, 'PROXIWARE_SLOT_FEED_URL', 'http://127.0.0.1:8100/internal/api/v1/proxiware-transfer-feed')
    monkeypatch.setattr(relay_sync, 'RELAY_FEED_KEY', 'feed-secret')
    monkeypatch.setattr(relay_sync, 'build_opener', lambda *_args: Opener())
    monkeypatch.setattr(relay_sync, 'conn', lambda: pytest.fail('failed feed must not open the relay database'))

    with pytest.raises(URLError):
        relay_sync.run_sync()


def test_prefixed_template_uses_prefixed_asset_and_navigation_paths(monkeypatch):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'URL_PREFIX', '/admin/transfer-proxy')
    with relay_app.app.test_request_context('/'):
        assert relay_app.relay_path('/') == '/admin/transfer-proxy/'
        assert relay_app.relay_path('/static/app.css') == '/admin/transfer-proxy/static/app.css'

def test_web_bind_accepts_explicit_internal_settings(monkeypatch):
    monkeypatch.setenv('RELAY_WEB_HOST', '127.0.0.1')
    monkeypatch.setenv('RELAY_WEB_PORT', '8123')
    assert web_bind() == ('127.0.0.1', 8123)

def test_session_cookie_is_secure_httponly_and_samesite():
    assert app.config['SESSION_COOKIE_SECURE'] is True
    assert app.config['SESSION_COOKIE_HTTPONLY'] is True
    assert app.config['SESSION_COOKIE_SAMESITE']=='Lax'
def test_parse_colon():
    assert parse_proxy_line('host.example:8080:user:pass')['username']=='user'





def test_parse_url():
    p=parse_proxy_line('socks5://u:p@host:9')
    assert p['protocol']=='socks5' and p['host']=='host' and p['username']=='u'

def test_format_endpoint_for_copy():
    row={'http_port':20001,'socks_port':30001}
    assert format_endpoint(row,'http','42.96.12.142','client','secret') == '42.96.12.142:20001:client:secret'
    assert format_endpoint(row,'socks5','42.96.12.142','client','secret') == '42.96.12.142:30001:client:secret'

def test_format_raw_proxy_uses_upstream_credentials():
    row={'host':'raw.example','port':44198,'username':'up-user','password':'up-pass'}
    assert format_raw_proxy(row)=='raw.example:44198:up-user:up-pass'

def test_duplicate_raw_csv_groups_proxies_by_exit_ip():
    rows=[
        {'host':'a','port':1,'username':'u1','password':'p1','exit_ip':'1.1.1.1'},
        {'host':'b','port':2,'username':'u2','password':'p2','exit_ip':'1.1.1.1'},
        {'host':'c','port':3,'username':'u3','password':'p3','exit_ip':'2.2.2.2'},
    ]
    output=duplicate_raw_csv(rows)
    assert 'duplicate_group,shared_exit_ip,total_raw_proxies,raw_proxy_1,raw_proxy_2' in output
    assert 'GROUP-001,1.1.1.1,2,a:1:u1:p1,b:2:u2:p2' in output
    assert '2.2.2.2' not in output

def test_client_port_keeps_stored_protocol_port():
    assert client_port({'detected_protocol':'socks5','http_port':20017,'socks_port':30017}) == 30017
    assert client_port({'detected_protocol':'socks5','http_port':20017,'socks_port':30017},'auto') == 30017
    assert client_port({'detected_protocol':'http','http_port':20017,'socks_port':30017}) == 20017

def test_job_snapshot_includes_percentage():
    assert job_snapshot({'status':'running','total':8,'done':3}) == {'status':'running','total':8,'done':3,'percent':38}
    assert job_snapshot({'status':'done','total':0,'done':0})['percent'] == 100

def test_batch_check_does_not_commit_mass_failure_when_all_checks_fail():
    assert should_commit_check_results(100, 0) is False
    assert should_commit_check_results(100, 50) is True
    assert should_commit_check_results(100, 0, 100) is False
    assert should_commit_check_results(1, 0) is True

def test_job_stop_flag_controls_cancellation():
    assert job_should_stop({'stop_requested':True}) is True
    assert job_should_stop({'status':'running'}) is False

def test_result_counts_reports_status_and_protocol_totals():
    rows=[{'status':'live','detected_protocol':'socks5'},{'status':'live_unverified','detected_protocol':'http'},{'status':'dead','detected_protocol':'unknown'},{'status':'blocked','detected_protocol':'socks5'},{'status':'inconclusive','detected_protocol':'unknown'}]
    assert result_counts(rows)=={'live':2,'live_verified':1,'live_unverified':1,'dead':1,'blocked':1,'inconclusive':1,'socks5':2,'http':1,'unknown':2}

def test_selected_ids_ignores_invalid_values():
    assert selected_ids(['1','bad','3']) == [1,3]

def test_unique_exit_rows_keeps_one_live_proxy_per_exit_ip():
    rows=[{'id':1,'status':'live','exit_ip':'1.1.1.1'}, {'id':2,'status':'live_unverified','exit_ip':'1.1.1.1'}, {'id':3,'status':'live_unverified','exit_ip':'2.2.2.2'}, {'id':4,'status':'dead','exit_ip':'3.3.3.3'}]
    assert [r['id'] for r in unique_exit_rows(rows)] == [1,3]

def test_proxy_page_keeps_raw_import_form():
    from pathlib import Path
    html=Path(__file__).parents[1].joinpath('templates','index.html').read_text()
    assert "action=\"{{ relay_path('/import') }}\"" in html
    assert 'name="lines"' in html

def test_progress_template_polls_rows_and_stats():
    from pathlib import Path
    html=Path(__file__).parents[1].joinpath('templates','index.html').read_text()
    assert "relay_path('/job/')" in html and "+'/rows'" in html
    assert 'data-proxy-id' in html
    assert 'data.live' in html
    assert 'data.live_unverified' in html

def test_proxy_page_distinguishes_tls_unverified_live_status():
    html=pathlib.Path(__file__).parents[1].joinpath('templates','index.html').read_text()
    assert 'Live TLS unverified' in html
    assert 'value="live_unverified"' in html
    assert "p.status in ('live','live_unverified')" in html
    assert "status-label" in html
    assert 'Inconclusive' in html
    assert 'failure_streak' in html

def test_duplicate_page_explains_usable_live_scope():
    html=pathlib.Path(__file__).parents[1].joinpath('templates','duplicates.html').read_text()
    assert 'verified and TLS-unverified live upstreams' in html

def test_progress_template_shows_inconclusive_count_and_retry_streak():
    html=pathlib.Path(__file__).parents[1].joinpath('templates','index.html').read_text()
    assert 'Inconclusive' in html
    assert 'failure_streak' in html

def test_only_running_job_is_active():
    jobs={'old':{'status':'done'},'current':{'status':'running'},'stopped':{'status':'stopped'}}
    assert active_job_id(jobs)=='current'

def test_terminal_job_states_stop_polling():
    for status in ('done','stopped','warning','failed','missing'):
        assert terminal_job(status)
    assert not terminal_job('running')

def test_proxy_counts_reports_all_operational_buckets():
    c=sqlite3.connect(':memory:')
    c.row_factory=sqlite3.Row
    c.execute('create table proxies(status text, detected_protocol text, error text, exit_ip text, last_check_status text, failure_streak integer)')
    c.executemany('insert into proxies values(?,?,?,?,?,?)',[
        ('live','socks5','', '1.1.1.1','live',0),
        ('live','http','', '2.2.2.2','live',0),
        ('live_unverified','socks5','', '3.3.3.3','live_unverified',0),
        ('dead','unknown','timeout', '','dead',3),
        ('blocked','socks5','provider_blocked', '','blocked',0),
        ('inconclusive','unknown','timeout', '','inconclusive',1),
        ('unknown',None,'', '','unknown',0),
    ])
    assert proxy_counts(c)=={
        'total':7,'live':3,'live_verified':2,'live_unverified':1,'dead':1,'blocked':1,'inconclusive':1,'unknown':1,'error':3,
        'socks5':3,'http':1,'unknown_protocol':3,'unique_exit':3,
    }

def test_build_proxy_filters_supports_each_visible_column():
    clause,params=build_proxy_filters({
        'upstream':'proxyvt.com:44198','protocol':'socks5','endpoint':'30001',
        'status':'live','exit_ip':'14.236.54.165',
    }, public_ip='42.96.12.142')
    assert 'host like ?' in clause and 'cast(port as text) like ?' in clause
    assert "case when detected_protocol in ('http','socks5') then detected_protocol else 'unknown' end=?" in clause
    assert "coalesce(status,'unknown')=?" in clause
    assert 'exit_ip like ?' in clause
    assert 'cast(socks_port as text) like ?' in clause
    assert params[-1]=='%30001%'

def test_unknown_protocol_filter_matches_rows_displayed_as_unknown():
    clause,params=build_proxy_filters({'protocol':'unknown'})
    assert "case when detected_protocol in ('http','socks5') then detected_protocol else 'unknown' end=?" in clause
    assert params==['unknown']

def test_usable_status_filter_matches_both_live_statuses():
    clause,params=build_proxy_filters({'status':'usable'})
    assert "status in ('live','live_unverified')" in clause
    assert params==[]

def test_inconclusive_filter_includes_live_rows_waiting_for_retry():
    clause,params=build_proxy_filters({'status':'inconclusive'})
    assert "last_check_status='inconclusive'" in clause
    assert params==[]

def test_inconclusive_check_preserves_live_mapping_until_threshold():
    row={'status':'live','detected_protocol':'socks5','exit_ip':'203.0.113.40','failure_streak':0}
    result={'status':'inconclusive','protocol':'unknown','exit_ip':'','latency_ms':None,'error':'timeout'}

    first=apply_check_result(row,result)
    second=apply_check_result({**row,**first},result)

    assert first['status']=='live' and first['failure_streak']==1
    assert second['status']=='live' and second['failure_streak']==2
    assert first['detected_protocol']=='socks5' and first['exit_ip']=='203.0.113.40'

def test_third_consecutive_failure_marks_proxy_dead():
    row={'status':'live','detected_protocol':'socks5','exit_ip':'203.0.113.41','failure_streak':FAILURE_THRESHOLD-1}
    result={'status':'dead','protocol':'unknown','exit_ip':'','latency_ms':None,'error':'connection refused'}

    updates=apply_check_result(row,result)

    assert updates['status']=='dead'
    assert updates['failure_streak']==FAILURE_THRESHOLD
    assert updates['detected_protocol']=='unknown'
    assert updates['exit_ip']==''

def test_successful_check_resets_failure_streak_and_updates_mapping():
    row={'status':'live','detected_protocol':'socks5','exit_ip':'203.0.113.42','failure_streak':2}
    result={'status':'live','protocol':'http','exit_ip':'203.0.113.43','latency_ms':321,'error':''}

    updates=apply_check_result(row,result)

    assert updates['status']=='live'
    assert updates['failure_streak']==0
    assert updates['detected_protocol']=='http'
    assert updates['exit_ip']=='203.0.113.43'

def test_blocked_result_is_immediate_and_resets_failure_streak():
    row={'status':'live','detected_protocol':'socks5','exit_ip':'203.0.113.44','failure_streak':2}
    result={'status':'blocked','protocol':'socks5','exit_ip':'','latency_ms':900,'error':'provider_blocked'}

    updates=apply_check_result(row,result)

    assert updates['status']=='blocked'
    assert updates['failure_streak']==0

def test_transient_failure_does_not_resurrect_dead_or_blocked_status():
    result={'status':'inconclusive','protocol':'unknown','exit_ip':'','latency_ms':None,'error':'timeout'}
    assert apply_check_result({'status':'dead','detected_protocol':'unknown','exit_ip':'','failure_streak':3},result)['status']=='dead'
    assert apply_check_result({'status':'blocked','detected_protocol':'socks5','exit_ip':'','failure_streak':0},result)['status']=='blocked'

def test_pagination_window_keeps_first_last_and_nearby_pages():
    assert pagination_window(1,83)==[1,2,3,None,83]
    assert pagination_window(42,83)==[1,None,40,41,42,43,44,None,83]
    assert pagination_window(83,83)==[1,None,81,82,83]

def test_proxy_page_has_counts_column_filters_and_direct_page_selection():
    html=pathlib.Path(__file__).parents[1].joinpath('templates','index.html').read_text()
    for marker in ('summary-grid','name="upstream"','name="endpoint"','name="exit_ip"','name="page"','name="per_page"'):
        assert marker in html
    assert 'Showing {{first_record}}-{{last_record}} of {{filtered_total}}' in html
    assert 'messages[-1]' in html
    assert 'Unknown protocol' in html and 'Unknown status' in html
    assert 'focus()' in html

def test_service_units_wait_for_network_and_apply_restart_hardening():
    root=pathlib.Path(__file__).parents[1]
    for name in ('proxy-relay.service','proxy-relay-engine.service'):
        unit=root.joinpath('deploy',name).read_text()
        assert 'Wants=network-online.target' in unit
        assert 'StartLimitIntervalSec=60' in unit
        assert 'StartLimitBurst=10' in unit
        assert 'Restart=always' in unit
        assert 'TimeoutStopSec=15' in unit
        assert 'UMask=0077' in unit

def test_web_service_is_loopback_only_and_health_monitor_is_installed():
    root=pathlib.Path(__file__).parents[1]
    unit=root.joinpath('deploy','proxy-relay.service').read_text()
    installer=root.joinpath('deploy','install.sh').read_text()
    caddy=root.joinpath('deploy','Caddyfile').read_text()
    assert 'Environment=RELAY_WEB_HOST=127.0.0.1' in unit
    assert 'Environment=RELAY_WEB_PORT=8000' in unit
    assert 'reverse_proxy 127.0.0.1:8000' in caddy
    assert 'proxy-relay-healthcheck.timer' in installer
    assert 'caddy' in installer
    assert 'for unit in proxy-relay-engine proxy-relay; do' in installer
    assert 'systemctl restart "$unit"' in installer
    assert 'go build -trimpath -o /usr/local/bin/proxy-relay-engine .' in installer

def test_health_monitor_uses_consecutive_failures_and_resource_thresholds():
    root=pathlib.Path(__file__).parents[1]
    script=root.joinpath('deploy','proxy-relay-healthcheck.sh').read_text()
    unit=root.joinpath('deploy','proxy-relay-healthcheck.service').read_text()
    assert 'ALERT_AFTER=3' in script
    assert 'cpu_percent' in script and 'memory_percent' in script and 'disk_percent' in script
    assert 'StateDirectory=proxy-relay-monitor' in unit


def test_health_monitor_matches_configured_ports_instead_of_counting_every_socket():
    root=pathlib.Path(__file__).parents[1]
    script=root.joinpath('deploy','proxy-relay-healthcheck.sh').read_text()
    assert 'expected_ports' in script
    assert 'subprocess.check_output(["ss", "-ltnH"], text=True)' in script
    assert 'missing_ports' in script

def test_installer_enables_daily_backup_timer():
    root=pathlib.Path(__file__).parents[1]
    installer=root.joinpath('deploy','install.sh').read_text()
    timer=root.joinpath('deploy','proxy-relay-backup.timer').read_text()
    assert 'proxy-relay-backup.timer' in installer
    assert 'OnCalendar=daily' in timer

def test_login_limiter_locks_after_repeated_failures():
    import app as relay_app
    relay_app.LOGIN_ATTEMPTS.clear()
    ip='203.0.113.9'
    for second in range(5):
        relay_app.record_login_failure(ip,now=1000+second)
    locked,retry_after=relay_app.login_guard_state(ip,now=1005)
    assert locked is True
    assert retry_after > 0
    relay_app.clear_login_failures(ip)
    assert relay_app.login_guard_state(ip,now=1005)==(False,0)

def test_login_route_returns_429_after_five_failures():
    import app as relay_app
    relay_app.LOGIN_ATTEMPTS.clear()
    headers={'X-Forwarded-For':'203.0.113.77'}
    with relay_app.app.test_client() as client:
        for _ in range(4):
            response=client.post('/login',data={'username':'wrong','password':'wrong'},headers=headers)
            assert response.status_code==401
        response=client.post('/login',data={'username':'wrong','password':'wrong'},headers=headers)
    assert response.status_code==429
    assert response.headers['Retry-After']
    assert b'Too many failed attempts' in response.data

def test_installer_allows_full_fixed_port_ranges():
    script=pathlib.Path(__file__).parents[1].joinpath('deploy','install.sh').read_text()
    assert 'ufw allow 20001:29999/tcp' in script
    assert 'ufw allow 30001:39999/tcp' in script

def test_import_form_is_open_by_default_for_discoverability():
    html=pathlib.Path(__file__).parents[1].joinpath('templates','index.html').read_text()
    assert '<details open class="card import-card">' in html

def test_health_endpoint_is_available_without_login(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    with app.test_client() as client:
        response=client.get('/healthz')
    assert response.status_code==200
    assert response.get_json()['status']=='ok'

def test_index_and_duplicates_render_with_real_sqlite_rows(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    c=relay_app.conn()
    c.execute("insert into proxies(host,port,username,password,protocol,status,detected_protocol,exit_ip,http_port,socks_port,error) values(?,?,?,?,?,?,?,?,?,?,?)",('upstream',8080,'u','p','auto','live','socks5','203.0.113.7',20001,30001,''))
    c.execute("insert into proxies(host,port,username,password,protocol,status,detected_protocol,exit_ip,http_port,socks_port,error) values(?,?,?,?,?,?,?,?,?,?,?)",('upstream2',8081,'u','p','auto','dead',None,'',20002,30002,'timeout'))
    c.commit(); c.close()
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        index=client.get('/?per_page=10')
        duplicates=client.get('/duplicates?per_page=10')
    assert index.status_code==200 and b'Proxy inventory' in index.data and b'Live' in index.data
    assert duplicates.status_code==200 and b'Duplicate exit IPs' in duplicates.data

def test_realtime_status_update_does_not_use_inner_html():
    html=pathlib.Path(__file__).parents[1].joinpath('templates','index.html').read_text()
    assert 'innerHTML' not in html

def test_empty_check_selection_is_a_noop_not_check_all(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    calls=[]
    monkeypatch.setattr(relay_app,'check_proxy',lambda proxy:calls.append(proxy) or {'status':'dead','protocol':'unknown','exit_ip':'','latency_ms':None,'error':'unexpected'})
    monkeypatch.setattr(relay_app,'reload_relay',lambda **_kwargs:True)
    c=relay_app.conn(); c.execute("insert into proxies(host,port,status,detected_protocol,http_port,socks_port) values('upstream',8080,'live','socks5',20001,30001)"); c.commit(); c.close()
    relay_app.JOBS['empty']={'status':'running','total':0,'done':0,'ids':[],'row_results':{}}
    relay_app.run_check_ids([],concurrency=1,job_id='empty')
    assert calls==[]
    assert relay_app.conn().execute('select status from proxies').fetchone()['status']=='live'
    assert relay_app.JOBS['empty']['status']=='done'

def test_all_failed_batch_preserves_database_statuses(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    monkeypatch.setattr(relay_app,'check_proxy',lambda proxy:{'status':'dead','protocol':'unknown','exit_ip':'','latency_ms':None,'error':'timeout'})
    monkeypatch.setattr(relay_app,'reload_relay',lambda:None)
    c=relay_app.conn()
    ids=[]
    for index in range(2):
        cur=c.execute("insert into proxies(host,port,status,detected_protocol,exit_ip,http_port,socks_port) values(?,?,?,?,?,?,?)",(f'upstream-{index}',8080+index,'live','socks5',f'203.0.113.{index+1}',20001+index,30001+index)); ids.append(cur.lastrowid)
    c.commit(); c.close()
    relay_app.JOBS['failed-batch']={'status':'running','total':2,'done':0,'ids':ids,'row_results':{}}
    relay_app.run_check_ids(ids,concurrency=2,job_id='failed-batch')
    statuses=[r['status'] for r in relay_app.conn().execute('select status from proxies order by id')]
    assert statuses==['live','live']
    assert relay_app.JOBS['failed-batch']['status']=='warning'

def test_inconclusive_result_is_recorded_without_closing_existing_listener(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    monkeypatch.setattr(relay_app,'check_proxy',lambda proxy:{'status':'inconclusive','protocol':'unknown','exit_ip':'','latency_ms':None,'error':'timeout'})
    monkeypatch.setattr(relay_app,'reload_relay',lambda:None)
    c=relay_app.conn(); cur=c.execute("insert into proxies(host,port,status,detected_protocol,exit_ip,http_port,socks_port) values(?,?,?,?,?,?,?)",('upstream',8080,'live','socks5','203.0.113.50',20001,30001)); pid=cur.lastrowid; c.commit(); c.close()
    relay_app.JOBS['inconclusive-record']={'status':'running','total':1,'done':0,'ids':[pid],'row_results':{}}

    relay_app.run_check_ids([pid],concurrency=1,job_id='inconclusive-record')

    row=relay_app.conn().execute('select status,last_check_status,failure_streak,detected_protocol,exit_ip,error from proxies').fetchone()
    assert tuple(row)==('live','inconclusive',1,'socks5','203.0.113.50','timeout')

def test_three_inconclusive_results_eventually_close_listener(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    monkeypatch.setattr(relay_app,'check_proxy',lambda proxy:{'status':'inconclusive','protocol':'unknown','exit_ip':'','latency_ms':None,'error':'timeout'})
    reload_calls=[]
    monkeypatch.setattr(relay_app,'reload_relay',lambda:reload_calls.append(True))
    c=relay_app.conn(); cur=c.execute("insert into proxies(host,port,status,detected_protocol,exit_ip,http_port,socks_port) values(?,?,?,?,?,?,?)",('upstream',8080,'live','socks5','203.0.113.51',20001,30001)); pid=cur.lastrowid; c.commit(); c.close()
    for index in range(3):
        relay_app.JOBS[f'inconclusive-{index}']={'status':'running','total':1,'done':0,'ids':[pid],'row_results':{}}
        relay_app.run_check_ids([pid],concurrency=1,job_id=f'inconclusive-{index}')

    row=relay_app.conn().execute('select status,last_check_status,failure_streak,detected_protocol,exit_ip from proxies').fetchone()
    assert tuple(row)==('dead','inconclusive',3,'unknown','')
    assert reload_calls

def test_all_tls_unverified_batch_is_committed_as_usable(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    monkeypatch.setattr(relay_app,'check_proxy',lambda proxy,**_kwargs:{'status':'live_unverified','protocol':'socks5','exit_ip':'203.0.113.30','latency_ms':15,'error':'TLS certificate verification failed'})
    monkeypatch.setattr(relay_app,'reload_relay',lambda **_kwargs:True)
    c=relay_app.conn(); ids=[]
    for index in range(2):
        cur=c.execute("insert into proxies(host,port,status,http_port,socks_port) values(?,?,?,?,?)",(f'upstream-{index}',9000+index,'unknown',20001+index,30001+index)); ids.append(cur.lastrowid)
    c.commit(); c.close()
    relay_app.JOBS['tls-batch']={'status':'running','total':2,'done':0,'ids':ids,'row_results':{}}

    relay_app.run_check_ids(ids,concurrency=2,job_id='tls-batch')

    rows=relay_app.conn().execute('select status,detected_protocol,exit_ip from proxies order by id').fetchall()
    assert [row['status'] for row in rows]==['live_unverified','live_unverified']
    assert all(row['detected_protocol']=='socks5' and row['exit_ip']=='203.0.113.30' for row in rows)
    assert relay_app.JOBS['tls-batch']['status']=='done'
    assert relay_app.JOBS['tls-batch']['live']==2
    assert relay_app.JOBS['tls-batch']['live_unverified']==2
    assert all(row['transfer_checked_at'] for row in relay_app.conn().execute('select transfer_checked_at from proxies'))


def test_direct_live_result_stays_non_online_when_transfer_probe_fails(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    monkeypatch.setattr(relay_app, 'check_proxy', lambda _proxy, **_kwargs: {'status': 'live', 'protocol': 'socks5', 'exit_ip': '203.0.113.70', 'latency_ms': 20, 'error': ''})
    monkeypatch.setattr(relay_app, 'check_relay_proxy', lambda *_args, **_kwargs: {'status': 'inconclusive', 'protocol': 'socks5', 'exit_ip': '', 'latency_ms': None, 'error': 'relay connect failed'}, raising=False)
    monkeypatch.setattr(relay_app, 'reload_relay', lambda **_kwargs: True)
    c = relay_app.conn()
    proxy_id = c.execute("insert into proxies(host,port,protocol,status,detected_protocol,http_port,socks_port) values(?,?,?,?,?,?,?)", ('upstream.example', 1080, 'socks5', 'unknown', 'socks5', 20001, 30001)).lastrowid
    c.commit()
    c.close()

    relay_app.run_check_ids([proxy_id], concurrency=1)

    row = relay_app.conn().execute('select status,last_check_status,exit_ip from proxies where id=?', (proxy_id,)).fetchone()
    assert tuple(row) == ('inconclusive', 'inconclusive', '203.0.113.70')


def test_proxy_is_online_only_after_listener_probe_matches_upstream_egress(monkeypatch, tmp_path):
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))
    monkeypatch.setattr(relay_app, 'reload_relay', lambda **_kwargs: True)
    def check(proxy, **_kwargs):
        return {'status':'live','protocol':'socks5','exit_ip':'203.0.113.71','latency_ms':12,'error':''}
    monkeypatch.setattr(relay_app, 'check_proxy', check)
    c = relay_app.conn()
    proxy_id = c.execute("insert into proxies(host,port,protocol,status,detected_protocol,http_port,socks_port) values(?,?,?,?,?,?,?)", ('upstream.example', 1080, 'socks5', 'unknown', 'socks5', 20002, 30002)).lastrowid
    c.commit()
    c.close()

    relay_app.run_check_ids([proxy_id], concurrency=1)

    row = relay_app.conn().execute('select status,last_check_status,exit_ip,transfer_checked_at from proxies where id=?', (proxy_id,)).fetchone()
    assert row['status'] == 'live'
    assert row['last_check_status'] == 'live'
    assert row['exit_ip'] == '203.0.113.71'
    assert row['transfer_checked_at']


def test_listener_probe_rejects_different_egress_identity(monkeypatch):
    import app as relay_app

    calls = []
    monkeypatch.setattr(relay_app, 'check_proxy', lambda proxy, **_kwargs: calls.append(proxy) or {
        'status':'live','protocol':'socks5','exit_ip':'203.0.113.99','latency_ms':10,'error':''
    })
    row={'detected_protocol':'socks5','provider_slot_key':'pw1_'+'f'*64,'listener_port':30123,'socks_port':30123,'http_port':20123}

    result=relay_app.check_relay_proxy(row,'203.0.113.71')

    assert result['status']=='inconclusive'
    assert 'did not match' in result['error']
    assert calls[0]['host']=='127.0.0.1' and calls[0]['port']==30123

def test_reload_relay_includes_verified_and_tls_unverified_rows(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    calls=[]
    monkeypatch.setattr(relay_app.subprocess,'run',lambda command,**kwargs:calls.append(command))
    c=relay_app.conn()
    c.executemany('''insert into proxies(host,port,username,password,status,detected_protocol,http_port,socks_port,enabled)
        values(?,?,?,?,?,?,?,?,?)''',[
        ('verified.example',8001,'u1','p1','live','http',20001,30001,1),
        ('tls.example',8002,'u2','p2','live_unverified','socks5',20002,30002,1),
        ('blocked.example',8003,'u3','p3','blocked','socks5',20003,30003,1),
    ])
    c.commit(); c.close()

    relay_app.reload_relay()

    import json
    data=json.loads((tmp_path/'relay.json').read_text())
    assert [(entry['host'],entry['protocol'],entry['port']) for entry in data['entries']]==[
        ('verified.example','http',20001),('tls.example','socks5',30002),
    ]
    assert calls and calls[0][-1]=='proxy-relay-engine'


def test_reload_relay_waits_for_matching_engine_revision(monkeypatch, tmp_path):
    from types import SimpleNamespace
    import json
    import app as relay_app

    monkeypatch.setattr(relay_app, 'ROOT', str(tmp_path))
    monkeypatch.setattr(relay_app, 'DB', str(tmp_path / 'relay.db'))

    def acknowledge(_command, **_kwargs):
        config = json.loads((tmp_path / 'relay.json').read_text())
        (tmp_path / 'relay.json.loaded').write_text(config['revision'])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(relay_app.subprocess, 'run', acknowledge)
    c = relay_app.conn()
    c.execute("insert into proxies(host,port,status,detected_protocol,http_port,socks_port) values('upstream',8080,'checking','socks5',20001,30001)")
    c.commit()
    c.close()

    assert relay_app.reload_relay(wait=True, timeout=0.2) is True
    (tmp_path / 'relay.json.loaded').write_text('stale-revision')
    monkeypatch.setattr(relay_app.subprocess, 'run', lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    assert relay_app.reload_relay(wait=True, timeout=0.05) is False

def test_exports_include_tls_unverified_client_endpoint(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    c=relay_app.conn()
    c.execute("insert into proxies(host,port,status,detected_protocol,exit_ip,http_port,socks_port) values(?,?,?,?,?,?,?)",('tls.example',8080,'live_unverified','socks5','203.0.113.31',20001,30001))
    c.commit(); c.close()
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        txt=client.get('/export/txt')
        csv_response=client.get('/export/csv')
    assert txt.status_code==200 and b':30001:' in txt.data
    assert csv_response.status_code==200 and b'live_unverified' in csv_response.data and b':30001:' in csv_response.data

def test_duplicate_groups_include_verified_and_tls_unverified_rows(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    c=relay_app.conn()
    c.executemany('''insert into proxies(host,port,username,password,status,detected_protocol,exit_ip,http_port,socks_port)
        values(?,?,?,?,?,?,?,?,?)''',[
        ('verified.example',8080,'u1','p1','live','http','203.0.113.32',20001,30001),
        ('tls.example',1080,'u2','p2','live_unverified','socks5','203.0.113.32',20002,30002),
    ])
    c.commit(); c.close()
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        page=client.get('/duplicates')
        report=client.get('/duplicates/export/raw')
    assert page.status_code==200 and b'2 proxies' in page.data and b':30002:' in page.data
    assert report.status_code==200 and b'verified.example:8080:u1:p1' in report.data and b'tls.example:1080:u2:p2' in report.data

def test_invalid_pagination_parameters_fall_back_to_safe_defaults(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        assert client.get('/?page=bad&per_page=bad').status_code==200
        assert client.get('/duplicates?page=bad&per_page=bad&min_count=bad').status_code==200

def test_conn_migrates_import_batch_schema_idempotently(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    c=relay_app.conn(); c.close()
    c=relay_app.conn()
    columns={row['name'] for row in c.execute('pragma table_info(proxies)')}
    assert 'import_batch_id' in columns
    assert c.execute("select name from sqlite_master where type='table' and name='import_batches'").fetchone()
    assert c.execute("select count(*) from settings where key in ('next_http_port','next_socks_port')").fetchone()[0] == 2
    c.close()

def test_conn_migrates_existing_database_without_tagging_legacy_rows(monkeypatch,tmp_path):
    import app as relay_app
    db=tmp_path/'relay.db'
    c=sqlite3.connect(db)
    c.execute('''create table proxies(id integer primary key, host text not null, port integer not null, username text, password text, protocol text default 'auto', status text default 'unknown', detected_protocol text, exit_ip text, latency_ms integer, error text, http_port integer unique, socks_port integer unique, enabled integer default 1, created_at text default current_timestamp, checked_at text)''')
    c.execute("insert into proxies(host,port,http_port,socks_port) values('legacy.example',8080,20042,30042)")
    c.commit(); c.close()
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(db))
    c=relay_app.conn(); row=c.execute('select import_batch_id from proxies').fetchone()
    assert row['import_batch_id'] is None
    assert relay_app.setting(c,'next_http_port')=='20043'
    assert relay_app.setting(c,'next_socks_port')=='30043'
    c.close()

def test_port_allocator_is_monotonic_after_proxy_deletion(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    c=relay_app.conn()
    first=relay_app.next_ports(c)
    c.execute("insert into proxies(host,port,http_port,socks_port) values(?,?,?,?)",('one',1,*first))
    c.commit(); c.execute('delete from proxies where host=?',('one',)); c.commit()
    second=relay_app.next_ports(c)
    assert second[0] > first[0] and second[1] > first[1]
    c.close()

def test_import_creates_batch_and_assigns_only_new_rows(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    monkeypatch.setattr(relay_app,'reload_relay',lambda:None)
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        response=client.post('/import',data={'lines':'new.example:8080:user:pass\nnew.example:8080:user:pass'})
    assert response.status_code==302
    c=relay_app.conn()
    batch=c.execute('select * from import_batches order by id desc limit 1').fetchone()
    row=c.execute('select * from proxies where host=?',('new.example',)).fetchone()
    assert batch['added_count']==1 and batch['duplicate_count']==1
    assert row['import_batch_id']==batch['id']
    c.close()

def test_undo_last_import_removes_batch_rows_but_preserves_legacy_rows(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    monkeypatch.setattr(relay_app,'reload_relay',lambda:None)
    c=relay_app.conn()
    c.execute("insert into proxies(host,port,http_port,socks_port) values(?,?,?,?)",('legacy.example',8000,20001,30001))
    c.commit(); c.close()
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        client.post('/import',data={'lines':'temporary.example:8080:user:pass'})
        response=client.post('/import/undo')
    assert response.status_code==302
    c=relay_app.conn()
    assert c.execute("select count(*) from proxies where host='temporary.example'").fetchone()[0]==0
    assert c.execute("select count(*) from proxies where host='legacy.example'").fetchone()[0]==1
    batch=c.execute('select undone_at,undone_count from import_batches order by id desc limit 1').fetchone()
    assert batch['undone_at'] and batch['undone_count']==1
    c.close()

def test_undo_import_rejects_running_check_job(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    relay_app.JOBS['running-undo-test']={'status':'running','total':1,'done':0}
    try:
        with relay_app.app.test_client() as client:
            with client.session_transaction() as session: session['admin']=True
            response=client.post('/import/undo')
        assert response.status_code==302
    finally:
        relay_app.JOBS.pop('running-undo-test',None)

def test_proxy_page_exposes_safe_undo_import_controls():
    html=pathlib.Path(__file__).parents[1].joinpath('templates','index.html').read_text()
    assert "action=\"{{ relay_path('/import/undo') }}\"" in html
    assert 'Undo last import' in html
    assert 'undo_batch' in html

def test_empty_import_does_not_create_an_undoable_batch(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        client.post('/import',data={'lines':'# comment\n'})
        response=client.get('/')
    assert b'undo_batch' not in response.data

def test_duplicate_only_newer_import_does_not_offer_undo_for_an_older_batch(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        client.post('/import',data={'lines':'first.example:8080:u:p'})
        client.post('/import',data={'lines':'first.example:8080:u:p'})
        response=client.get('/')
    assert b'Undo last import' not in response.data

def test_undo_marks_batch_and_second_undo_is_noop(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    monkeypatch.setattr(relay_app,'reload_relay',lambda:None)
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        client.post('/import',data={'lines':'one.example:8080:u:p'})
        first=client.post('/import/undo')
        second=client.post('/import/undo')
    assert first.status_code==302 and second.status_code==302
    c=relay_app.conn(); batch=c.execute('select undone_count from import_batches order by id desc limit 1').fetchone(); c.close()
    assert batch['undone_count']==1

def test_undo_counts_only_rows_still_present_in_the_batch(monkeypatch,tmp_path):
    import app as relay_app
    monkeypatch.setattr(relay_app,'ROOT',str(tmp_path))
    monkeypatch.setattr(relay_app,'DB',str(tmp_path/'relay.db'))
    monkeypatch.setattr(relay_app,'reload_relay',lambda:None)
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        client.post('/import',data={'lines':'one.example:8080:u:p\ntwo.example:8081:u:p'})
    c=relay_app.conn(); c.execute("delete from proxies where host='one.example'"); c.commit(); c.close()
    with relay_app.app.test_client() as client:
        with client.session_transaction() as session: session['admin']=True
        client.post('/import/undo')
    c=relay_app.conn(); remaining=c.execute('select host from proxies').fetchall(); batch=c.execute('select undone_count from import_batches order by id desc limit 1').fetchone(); c.close()
    assert [row['host'] for row in remaining]==[]
    assert batch['undone_count']==1
