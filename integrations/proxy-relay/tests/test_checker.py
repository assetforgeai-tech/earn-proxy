import pathlib
import sys
from collections import Counter
from types import SimpleNamespace
from urllib.parse import urlsplit

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
from checker import HTTP_PROBE_URLS, PROBE_URLS, PROXY_DEADLINE, check_proxy, parse_exit_ip


PROXY={'host':'upstream','port':1080,'username':'u','password':'p','protocol':'socks5'}


def curl_response(probe, ip='203.0.113.8', code='200', effective_url=None, returncode=0, stderr='', ssl_result='0'):
    effective_url=effective_url or probe
    body=(ip+'\n') if ip else ''
    return SimpleNamespace(
        returncode=returncode,
        stdout=f'{body}__PROBE_META__:{code}|{effective_url}|{ssl_result}\n',
        stderr=stderr,
    )


def test_exit_ip_parser_rejects_html_and_accepts_ip_literals():
    assert parse_exit_ip('203.0.113.8\n') == '203.0.113.8'
    assert parse_exit_ip('2001:db8::8\n') == '2001:db8::8'
    assert parse_exit_ip('<!doctype html><title>Portal</title>') == ''


def test_checker_uses_three_independent_https_probe_hosts():
    assert len(PROBE_URLS)==3
    assert all(url.startswith('https://') for url in PROBE_URLS)
    assert len({urlsplit(url).hostname for url in PROBE_URLS})==3


def test_checker_requires_two_matching_verified_endpoints_for_live():
    calls=[]
    def runner(cmd, **kwargs):
        calls.append(cmd)
        probe=cmd[-1]
        if probe==PROBE_URLS[0]:
            return curl_response(probe,ip='203.0.113.10')
        return curl_response(probe,ip='',code='503',returncode=0)

    result=check_proxy(PROXY,runner=runner)

    assert result['status']!='live'
    assert len({cmd[-1] for cmd in calls})==5


def test_checker_accepts_two_of_three_matching_verified_endpoints():
    ips={PROBE_URLS[0]:'203.0.113.11',PROBE_URLS[1]:'203.0.113.12',PROBE_URLS[2]:'203.0.113.11'}
    def runner(cmd, **kwargs):
        return curl_response(cmd[-1],ip=ips[cmd[-1]])

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='live'
    assert result['protocol']=='socks5'
    assert result['exit_ip']=='203.0.113.11'


def test_checker_falls_back_to_two_matching_plain_http_endpoints():
    def runner(cmd, **kwargs):
        probe=cmd[-1]
        if probe.startswith('https://'):
            return SimpleNamespace(returncode=28,stdout='',stderr='HTTPS unavailable')
        return curl_response(probe,ip='203.0.113.25')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='live'
    assert result['protocol']=='socks5'
    assert result['exit_ip']=='203.0.113.25'


def test_checker_does_not_mix_quorum_evidence_between_retries():
    attempt=Counter()
    first_ips={PROBE_URLS[0]:'203.0.113.26',PROBE_URLS[1]:'203.0.113.27',PROBE_URLS[2]:'203.0.113.28'}
    second_ips={PROBE_URLS[0]:'203.0.113.26',PROBE_URLS[1]:'203.0.113.28',PROBE_URLS[2]:'203.0.113.27'}
    def runner(cmd, **kwargs):
        probe=cmd[-1]
        attempt[probe]+=1
        ips=first_ips if attempt[probe]==1 else second_ips
        return curl_response(probe,ip=ips[probe])

    result=check_proxy(PROXY,runner=runner)

    assert result['status']!='live'


def test_checker_does_not_mix_missing_probe_evidence_between_retries():
    attempts=Counter()
    def runner(cmd, **kwargs):
        probe=cmd[-1]
        attempts[probe]+=1
        if probe in HTTP_PROBE_URLS:
            return SimpleNamespace(returncode=28,stdout='',stderr='timeout')
        if attempts[probe]==1 and probe==PROBE_URLS[2]:
            return SimpleNamespace(returncode=28,stdout='',stderr='timeout')
        if attempts[probe]==2 and probe==PROBE_URLS[1]:
            return SimpleNamespace(returncode=28,stdout='',stderr='timeout')
            if attempts[probe]==1:
                ip='203.0.113.29' if probe!=PROBE_URLS[1] else '203.0.113.30'
            else:
                ip='203.0.113.29' if probe==PROBE_URLS[0] else '203.0.113.30'
        return curl_response(probe,ip=ip)

    result=check_proxy(PROXY,runner=runner)

    assert result['status']!='live'


def test_checker_rejects_non_2xx_response_even_when_body_is_an_ip():
    def runner(cmd, **kwargs):
        return curl_response(cmd[-1],ip='203.0.113.13',code='503')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='dead'
    assert result['exit_ip']==''


def test_checker_rejects_effective_host_mismatch_even_when_body_is_an_ip():
    def runner(cmd, **kwargs):
        return curl_response(cmd[-1],ip='203.0.113.14',effective_url='https://unexpected.example/ip')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='dead'
    assert result['exit_ip']==''


def test_checker_retries_transient_failures_once_and_recovers():
    attempts=Counter()
    def runner(cmd, **kwargs):
        probe=cmd[-1]
        attempts[probe]+=1
        if attempts[probe]==1:
            return SimpleNamespace(returncode=28,stdout='',stderr='timeout')
        return curl_response(probe,ip='203.0.113.15')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='live'
    assert result['exit_ip']=='203.0.113.15'
    assert all(attempts[url]==2 for url in PROBE_URLS)


def test_checker_returns_inconclusive_when_all_attempts_timeout():
    calls=[]
    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=28,stdout='',stderr='timeout')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='inconclusive'
    assert result['protocol']=='unknown'
    assert result['exit_ip']==''
    assert len(calls)==10


def test_checker_requires_successful_curl_exit_for_quorum():
    def runner(cmd, **kwargs):
        return curl_response(cmd[-1],ip='203.0.113.16',returncode=28,stderr='transfer timed out')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='inconclusive'


def test_checker_accepts_matching_insecure_https_quorum_as_live_unverified():
    def runner(cmd, **kwargs):
        probe=cmd[-1]
        if '--insecure' in cmd:
            return curl_response(probe,ip='203.0.113.17',ssl_result='19')
        return SimpleNamespace(returncode=60,stdout='',stderr='certificate error')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='live_unverified'
    assert result['protocol']=='socks5'
    assert result['exit_ip']=='203.0.113.17'


def test_checker_rejects_mismatched_insecure_https_exit_ips():
    ips={PROBE_URLS[0]:'203.0.113.18',PROBE_URLS[1]:'203.0.113.19',PROBE_URLS[2]:'203.0.113.20'}
    def runner(cmd, **kwargs):
        probe=cmd[-1]
        if '--insecure' in cmd:
            return curl_response(probe,ip=ips[probe],ssl_result='19')
        return SimpleNamespace(returncode=60,stdout='',stderr='certificate error')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='inconclusive'
    assert result['exit_ip']==''


def test_captive_portal_wins_over_other_successes_for_same_protocol():
    def runner(cmd, **kwargs):
        probe=cmd[-1]
        if probe==PROBE_URLS[2]:
            return SimpleNamespace(
                returncode=0,
                stdout='<!doctype html><link href="/internet/logo.svg">\n'
                       '__PROBE_META__:200|https://giahan.vnpt.com.vn/internet/|19\n',
                stderr='',
            )
        return curl_response(probe,ip='203.0.113.21')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='blocked'
    assert result['exit_ip']==''
    assert 'giahan.vnpt.com.vn' in result['error']


def test_captive_portal_on_http_fallback_wins_over_verified_https_quorum():
    def runner(cmd, **kwargs):
        probe=cmd[-1]
        if probe.startswith('http://'):
            return SimpleNamespace(
                returncode=0,
                stdout='<!doctype html><link href="/internet/logo.svg">\n'
                       '__PROBE_META__:200|https://giahan.vnpt.com.vn/internet/|19\n',
                stderr='',
            )
        return curl_response(probe,ip='203.0.113.31')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='blocked'
    assert 'giahan.vnpt.com.vn' in result['error']


def test_insecure_captive_portal_remains_blocked():
    def runner(cmd, **kwargs):
        if '--insecure' in cmd:
            return SimpleNamespace(
                returncode=0,
                stdout='<!doctype html><link href="/internet/logo.svg">\n'
                       '__PROBE_META__:200|https://giahan.vnpt.com.vn/internet/|19\n',
                stderr='',
            )
        return SimpleNamespace(returncode=60,stdout='',stderr='certificate error')

    result=check_proxy(PROXY,runner=runner)

    assert result['status']=='blocked'


def test_auto_detection_checks_socks5_before_http():
    calls=[]
    def runner(cmd, **kwargs):
        calls.append(cmd)
        return curl_response(cmd[-1],ip='203.0.113.22')

    result=check_proxy({**PROXY,'protocol':'auto'},runner=runner)

    assert result['status']=='live'
    assert result['protocol']=='socks5'
    assert calls[0][calls[0].index('--proxy')+1].startswith('socks5h://')
    assert not any(cmd[cmd.index('--proxy')+1].startswith('http://') for cmd in calls)


def test_auto_timeout_on_socks_falls_back_to_http():
    def runner(cmd, **kwargs):
        proxy_url=cmd[cmd.index('--proxy')+1]
        if proxy_url.startswith('socks5h://'):
            return SimpleNamespace(returncode=28,stdout='',stderr='timeout')
        return curl_response(cmd[-1],ip='203.0.113.23')

    result=check_proxy({**PROXY,'protocol':'auto'},runner=runner)

    assert result['status']=='live'
    assert result['protocol']=='http'


def test_auto_keeps_preferred_socks5_when_tls_unverified_is_usable():
    calls=[]
    def runner(cmd, **kwargs):
        calls.append(cmd)
        proxy_url=cmd[cmd.index('--proxy')+1]
        if proxy_url.startswith('http://'):
            raise AssertionError('HTTP fallback must not run after usable SOCKS5 quorum')
        if '--insecure' in cmd:
            return curl_response(cmd[-1],ip='203.0.113.24',ssl_result='19')
        return SimpleNamespace(returncode=60,stdout='',stderr='certificate error')

    result=check_proxy({**PROXY,'protocol':'auto'},runner=runner)

    assert result['status']=='live_unverified'
    assert result['protocol']=='socks5'


def test_proxy_check_has_bounded_total_deadline_and_larger_slow_proxy_budget():
    assert 30 <= PROXY_DEADLINE <= 45
