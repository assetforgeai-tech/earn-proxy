import ipaddress, json, re, subprocess, threading, time
from collections import Counter
from urllib.parse import urlsplit

HTTP_PROBE_URLS=('http://ifconfig.me/ip','http://icanhazip.com')
PROXIO_WHOAMI_URL='https://api.prox.io.vn/v1/check/whoami'
PROXIO_MIN_INTERVAL_SECONDS=0.2
HTTPS_PROBE_URLS=('https://ifconfig.me/ip','https://icanhazip.com','https://checkip.amazonaws.com',PROXIO_WHOAMI_URL)
PROBE_URLS=HTTPS_PROBE_URLS
PROXY_DEADLINE=36
PROBE_ATTEMPTS=2
CAPTIVE_HOSTS={'giahan.vnpt.com.vn'}
CAPTIVE_MARKERS=('giahan.vnpt.com.vn','/internet/logo.svg','provider_blocked')
PROBE_META='__PROBE_META__:'
_proxio_rate_lock=threading.Lock()
_proxio_next_request_at=0.0


def parse_exit_ip(value):
    candidate=(value or '').strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ''


def parse_probe_exit_ip(probe, value):
    if str(probe or '').strip()!=PROXIO_WHOAMI_URL:
        return parse_exit_ip(value)
    try:
        payload=json.loads(str(value or ''))
    except (TypeError,ValueError,json.JSONDecodeError):
        return ''
    if not isinstance(payload,dict):
        return ''
    return parse_exit_ip(payload.get('ip'))


def _wait_for_probe_slot(probe,clock=time.monotonic,sleeper=time.sleep):
    if str(probe or '').strip()!=PROXIO_WHOAMI_URL:
        return
    global _proxio_next_request_at
    with _proxio_rate_lock:
        now=clock()
        delay=max(0.0,_proxio_next_request_at-now)
        if delay:
            sleeper(delay)
            now=clock()
        _proxio_next_request_at=max(now,_proxio_next_request_at)+PROXIO_MIN_INTERVAL_SECONDS


def captive_error(body, meta=''):
    text=(body or '').lower()
    fields=(meta or '').strip().split('|')
    effective_url=fields[1] if len(fields)>1 else ''
    host=(urlsplit(effective_url).hostname or '').lower()
    if host in CAPTIVE_HOSTS or any(marker in text for marker in CAPTIVE_MARKERS):
        return f'provider_blocked: captive portal redirected to {host or "provider portal"}'
    ssl_result=fields[2] if len(fields)>2 else '0'
    if ssl_result not in ('','0') and re.search(r'<(?:!doctype|html|head|body)\b',text):
        return 'provider_blocked: intercepted HTTPS response with an untrusted certificate'
    return ''


def _meta_valid(meta, probe, require_tls=False):
    fields=(meta or '').strip().split('|')
    code=fields[0] if fields else ''
    effective_url=fields[1] if len(fields)>1 else ''
    effective_host=(urlsplit(effective_url).hostname or '').lower()
    expected_host=(urlsplit(probe).hostname or '').lower()
    ssl_result=fields[2] if len(fields)>2 else '0'
    return (
        code.isdigit() and 200 <= int(code) < 300 and
        effective_host==expected_host and
        (not require_tls or ssl_result=='0')
    )


def _meta_http_code(meta):
    code=str(meta or '').strip().split('|',1)[0]
    return int(code) if code.isdigit() else 0


def _probe_endpoint_http_failure(response):
    code=_meta_http_code(response.get('meta',''))
    return code==429 or code>=500


def _probe_once(proxy_url, probe, insecure, timeout, runner):
    cmd=['curl','--silent','--show-error','--location','--max-redirs','3',
         '--connect-timeout',str(round(min(5,timeout),1)),
         '--max-time',str(round(min(8,timeout),1)),'--proxy',proxy_url]
    if insecure:
        cmd.append('--insecure')
    cmd += ['--write-out',f'\n{PROBE_META}%{{http_code}}|%{{url_effective}}|%{{ssl_verify_result}}\n',probe]
    try:
        if runner is subprocess.run:
            _wait_for_probe_slot(probe)
        result=runner(cmd,capture_output=True,text=True,timeout=timeout+1,check=False)
    except Exception as exc:
        return None,str(exc)
    parts=(result.stdout or '').split(PROBE_META,1)
    return {
        'returncode':result.returncode,
        'body':parts[0],
        'meta':parts[1] if len(parts)>1 else '',
        'stderr':(result.stderr or '').strip(),
    },''


def _quorum(results):
    valid=[]
    for probe,response in results.items():
        if not response or response['returncode']!=0 or not _meta_valid(response['meta'],probe,require_tls=True):
            continue
        ip=parse_probe_exit_ip(probe,response['body'])
        if ip:
            valid.append((probe,ip))
    counts=Counter(ip for _,ip in valid)
    if not counts:
        return ''
    ip,count=counts.most_common(1)[0]
    return ip if count>=2 else ''


def _insecure_quorum(results):
    valid=[]
    for probe,response in results.items():
        if not response or response['returncode']!=0 or not _meta_valid(response['meta'],probe):
            continue
        ip=parse_probe_exit_ip(probe,response['body'])
        if ip:
            valid.append((probe,ip))
    counts=Counter(ip for _,ip in valid)
    if not counts:
        return ''
    ip,count=counts.most_common(1)[0]
    return ip if count>=2 else ''


def _plain_http_quorum(results):
    valid=[]
    for probe,response in results.items():
        if not response or response['returncode']!=0 or not _meta_valid(response['meta'],probe):
            continue
        ip=parse_probe_exit_ip(probe,response['body'])
        if ip:
            valid.append(ip)
    counts=Counter(valid)
    if not counts:
        return ''
    ip,count=counts.most_common(1)[0]
    return ip if count>=2 else ''


def check_proxy(proxy, timeout=10, runner=subprocess.run):
    host,port=proxy['host'],str(proxy['port'])
    auth=f"{proxy['username']}:{proxy['password']}@" if proxy.get('username') else ''
    protocols=[]
    if proxy.get('protocol') in ('auto','socks5'):
        protocols.append(('socks5',f'socks5h://{auth}{host}:{port}'))
    if proxy.get('protocol') in ('auto','http','https'):
        protocols.append(('http',f'http://{auth}{host}:{port}'))
    errors=[]; blocked_results=[]; saw_transient=False; saw_uncertain=False; started=time.monotonic()
    deadline=started+max(PROXY_DEADLINE,max(1,timeout))
    for proto,proxy_url in protocols:
        verified={}; insecure={}; plain_http={}; protocol_blocked=[]
        for attempt in range(PROBE_ATTEMPTS):
            if time.monotonic()>=deadline: break
            verified_ip=''; insecure_ip=''; plain_http_ip=''
            remaining=max(1,deadline-time.monotonic())
            per_probe=max(1,min(8,remaining/(len(HTTPS_PROBE_URLS)+len(HTTP_PROBE_URLS))))
            # HTTPS is authoritative; HTTP endpoints provide compatibility evidence.
            for probe in HTTPS_PROBE_URLS:
                response,error=_probe_once(proxy_url,probe,False,per_probe,runner)
                if error: errors.append(error); saw_transient=True; continue
                blocked=captive_error(response['body'],response['meta'])
                if blocked: protocol_blocked.append(blocked); continue
                if _probe_endpoint_http_failure(response): saw_transient=True
                if response['returncode'] in (28,7,52,55,56): saw_transient=True
                verified[probe]=response
            if protocol_blocked:
                break
            ip=_quorum(verified)
            if ip:
                verified_ip=ip
            if any(response and response['returncode'] in (35,51,60) for response in verified.values()):
                saw_uncertain=True
                for probe in HTTPS_PROBE_URLS:
                    if time.monotonic()>=deadline: break
                    response,error=_probe_once(proxy_url,probe,True,per_probe,runner)
                    if error: errors.append(error); saw_transient=True; continue
                    blocked=captive_error(response['body'],response['meta'])
                    if blocked: protocol_blocked.append(blocked); continue
                    if _probe_endpoint_http_failure(response): saw_transient=True
                    if response['returncode'] in (28,7,52,55,56): saw_transient=True
                    insecure[probe]=response
                ip=_insecure_quorum(insecure)
                if ip:
                    insecure_ip=ip
                if protocol_blocked:
                    break
            for probe in HTTP_PROBE_URLS:
                if time.monotonic()>=deadline: break
                response,error=_probe_once(proxy_url,probe,False,per_probe,runner)
                if error: errors.append(error); saw_transient=True; continue
                blocked=captive_error(response['body'],response['meta'])
                if blocked: protocol_blocked.append(blocked); continue
                if _probe_endpoint_http_failure(response): saw_transient=True
                if response['returncode'] in (28,7,52,55,56): saw_transient=True
                plain_http[probe]=response
            ip=_plain_http_quorum(plain_http)
            if ip:
                plain_http_ip=ip
            if protocol_blocked:
                break
            if verified_ip:
                return {'status':'live','protocol':proto,'exit_ip':verified_ip,'latency_ms':round((time.monotonic()-started)*1000),'error':''}
            if insecure_ip:
                return {'status':'live_unverified','protocol':proto,'exit_ip':insecure_ip,'latency_ms':round((time.monotonic()-started)*1000),'error':'TLS certificate verification failed; exit IP confirmed by two independent HTTPS probes'}
            if plain_http_ip:
                return {'status':'live','protocol':proto,'exit_ip':plain_http_ip,'latency_ms':round((time.monotonic()-started)*1000),'error':''}
            verified={}; insecure={}; plain_http={}
            if attempt+1<PROBE_ATTEMPTS:
                continue
        blocked_results.extend((proto,error) for error in protocol_blocked)
    if blocked_results:
        proto,error=blocked_results[0]
        return {'status':'blocked','protocol':proto,'exit_ip':'','latency_ms':round((time.monotonic()-started)*1000),'error':error}
    status='inconclusive' if saw_transient or saw_uncertain or errors else 'dead'
    return {'status':status,'protocol':'unknown','exit_ip':'','latency_ms':None,'error':'; '.join(errors)[-500:] or 'insufficient independent probe evidence'}
