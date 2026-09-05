import base64, csv, hashlib, hmac, io, json, os, re, secrets, sqlite3, subprocess, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit, urlencode
from functools import wraps
from flask import Flask, request, redirect, session, render_template, Response, flash, jsonify
from checker import check_proxy

ROOT=os.environ.get('RELAY_ROOT','/opt/proxy-relay'); DB=os.path.join(ROOT,'relay.db'); CFG=os.path.join(ROOT,'3proxy.cfg')
HTTP_BASE=int(os.environ.get('HTTP_PORT_BASE','20001')); SOCKS_BASE=int(os.environ.get('SOCKS_PORT_BASE','30001'))
ADMIN_USER=os.environ.get('ADMIN_USER','admin'); ADMIN_PASS=os.environ.get('ADMIN_PASS','change-me'); CLIENT_USER=os.environ.get('CLIENT_USER','client'); CLIENT_PASS=os.environ.get('CLIENT_PASS','change-me'); PUBLIC_IP=os.environ.get('PUBLIC_IP','42.96.12.142')
URL_PREFIX=os.environ.get('RELAY_URL_PREFIX','').rstrip('/')
RELAY_FEED_KEY=os.environ.get('RELAY_FEED_KEY','')
RELAY_SSO_SECRET=os.environ.get('RELAY_SSO_SECRET','')
app=Flask(__name__); app.secret_key=os.environ.get('SESSION_SECRET','replace-me')
app.config.update(SESSION_COOKIE_NAME='relay_session',SESSION_COOKIE_PATH=URL_PREFIX or '/',SESSION_COOKIE_SECURE=True,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax')
CSRF_ENABLED=os.environ.get('RELAY_ENFORCE_CSRF','1' if URL_PREFIX else '0') == '1'
LOGIN_ATTEMPTS={}; LOGIN_LOCK=threading.Lock(); LOGIN_MAX_FAILURES=5; LOGIN_WINDOW=600; LOGIN_LOCK_SECONDS=900
LIVE_STATUSES=('live','live_unverified')
FAILURE_THRESHOLD=3

def is_usable_status(status):
    return status in LIVE_STATUSES

def web_bind():
    host=os.environ.get('RELAY_WEB_HOST','127.0.0.1')
    try:
        port=int(os.environ.get('RELAY_WEB_PORT','8000'))
    except (TypeError,ValueError):
        port=8000
    if not 1 <= port <= 65535:
        port=8000
    return host,port

def login_guard_state(ip,now=None):
    now=time.time() if now is None else now
    with LOGIN_LOCK:
        state=LOGIN_ATTEMPTS.get(ip,{'attempts':[],'locked_until':0})
        if state.get('locked_until',0)>now: return True,max(1,round(state['locked_until']-now))
        attempts=[value for value in state.get('attempts',[]) if value>=now-LOGIN_WINDOW]
        if not attempts:
            LOGIN_ATTEMPTS.pop(ip,None)
            return False,0
        state.update(attempts=attempts,locked_until=0); LOGIN_ATTEMPTS[ip]=state
        return False,0

def record_login_failure(ip,now=None):
    now=time.time() if now is None else now
    with LOGIN_LOCK:
        state=LOGIN_ATTEMPTS.get(ip,{'attempts':[],'locked_until':0})
        attempts=[value for value in state.get('attempts',[]) if value>=now-LOGIN_WINDOW]+[now]
        state={'attempts':attempts,'locked_until':now+LOGIN_LOCK_SECONDS if len(attempts)>=LOGIN_MAX_FAILURES else 0}
        LOGIN_ATTEMPTS[ip]=state
        return len(attempts)

def clear_login_failures(ip):
    with LOGIN_LOCK: LOGIN_ATTEMPTS.pop(ip,None)

def login_client_ip():
    forwarded=request.headers.get('X-Forwarded-For','')
    return (forwarded.rsplit(',',1)[-1].strip() if forwarded else request.remote_addr) or 'unknown'

def conn():
    os.makedirs(ROOT,exist_ok=True); c=sqlite3.connect(DB,timeout=30); c.row_factory=sqlite3.Row
    c.execute('''create table if not exists proxies(id integer primary key, host text not null, port integer not null, username text, password text, protocol text default 'auto', status text default 'unknown', detected_protocol text, exit_ip text, latency_ms integer, error text, http_port integer unique, socks_port integer unique, enabled integer default 1, created_at text default current_timestamp, checked_at text, import_batch_id integer, last_check_status text, failure_streak integer not null default 0)''')
    columns={row['name'] for row in c.execute('pragma table_info(proxies)')}
    if 'import_batch_id' not in columns: c.execute('alter table proxies add column import_batch_id integer')
    if 'last_check_status' not in columns: c.execute('alter table proxies add column last_check_status text')
    if 'failure_streak' not in columns: c.execute('alter table proxies add column failure_streak integer not null default 0')
    c.execute('''create table if not exists import_batches(
        id integer primary key,
        created_at text default current_timestamp,
        input_count integer not null default 0,
        added_count integer not null default 0,
        duplicate_count integer not null default 0,
        error_count integer not null default 0,
        undone_at text,
        undone_count integer not null default 0
    )''')
    c.execute('''create table if not exists settings(key text primary key,value text not null)''')
    c.execute("insert or ignore into settings values('check_concurrency','32')")
    for key,base in (('next_http_port',HTTP_BASE),('next_socks_port',SOCKS_BASE)):
        existing=c.execute('select value from settings where key=?',(key,)).fetchone()
        if not existing:
            column='http_port' if key=='next_http_port' else 'socks_port'
            maximum=c.execute(f'select max({column}) value from proxies').fetchone()['value']
            c.execute('insert into settings(key,value) values(?,?)',(key,str(max(base,(maximum or base-1)+1))))
    c.commit(); return c
def parse_proxy_line(line):
    line=line.strip();
    if not line or line.startswith('#'): raise ValueError('empty')
    proto='auto'
    m=re.match(r'^(https?|socks5)://(.+)$',line,re.I)
    if m:
        proto=m.group(1).lower(); parsed=urlsplit(line)
        if not parsed.hostname or not parsed.port: raise ValueError('invalid proxy URL')
        return {'host':parsed.hostname,'port':parsed.port,'username':parsed.username or '', 'password':parsed.password or '', 'protocol':proto}
    parts=line.rsplit(':',3)
    if len(parts)==4: host,port,user,password=parts
    elif len(parts)==2: host,port=parts; user=password=''
    else: raise ValueError('expected host:port[:user:password]')
    if not host or not port.isdigit() or not 1<=int(port)<=65535: raise ValueError('invalid host/port')
    return {'host':host,'port':int(port),'username':user,'password':password,'protocol':proto}
def next_ports(c):
    values=[]
    for key,base in (('next_http_port',HTTP_BASE),('next_socks_port',SOCKS_BASE)):
        row=c.execute('select value from settings where key=?',(key,)).fetchone()
        value=int(row['value']) if row else base
        column='http_port' if key=='next_http_port' else 'socks_port'
        while c.execute(f'select 1 from proxies where {column}=?',(value,)).fetchone():
            value += 1
        if value >= base + 9999:
            raise ValueError(f'no free {column} remaining')
        values.append(value)
        c.execute('insert or replace into settings(key,value) values(?,?)',(key,str(value+1)))
    return tuple(values)

def latest_undo_batch(c):
    return c.execute('''select b.*, count(p.id) remaining_count,
        sum(case when p.status in ('live','live_unverified') then 1 else 0 end) live_count,
        sum(case when p.checked_at is not null then 1 else 0 end) checked_count
        from import_batches b left join proxies p on p.import_batch_id=b.id
        where b.id=(select max(id) from import_batches) and b.undone_at is null
        group by b.id having count(p.id)>0''').fetchone()
def format_endpoint(row, protocol, public_ip=PUBLIC_IP, user=CLIENT_USER, password=CLIENT_PASS):
    port=row['http_port'] if protocol=='http' else row['socks_port']; return f'{public_ip}:{port}:{user}:{password}'
def format_raw_proxy(row):
    return f"{row['host']}:{row['port']}:{row['username'] or ''}:{row['password'] or ''}"
def duplicate_raw_csv(rows):
    groups={}
    for r in rows: groups.setdefault(r['exit_ip'],[]).append(format_raw_proxy(r))
    groups={exit_ip:proxies for exit_ip,proxies in groups.items() if len(proxies)>1}
    width=max((len(proxies) for proxies in groups.values()),default=0)
    out=io.StringIO(); w=csv.writer(out); w.writerow(['duplicate_group','shared_exit_ip','total_raw_proxies']+[f'raw_proxy_{i}' for i in range(1,width+1)])
    for index,(exit_ip,proxies) in enumerate(groups.items(),1): w.writerow([f'GROUP-{index:03d}',exit_ip,len(proxies)]+proxies+['']*(width-len(proxies)))
    return out.getvalue()
def client_port(row): return row['socks_port'] if row['detected_protocol']=='socks5' else row['http_port']
def unique_exit_rows(rows):
    seen=set(); result=[]
    for row in rows:
        if not is_usable_status(row['status']) or not row['exit_ip'] or row['exit_ip'] in seen: continue
        seen.add(row['exit_ip']); result.append(row)
    return result
JOBS={}; JOB_LOCK=threading.Lock()
TERMINAL_JOB_STATES={'done','stopped','warning','failed','missing'}

def relay_path(path='/'):
    value='/' + str(path or '').lstrip('/')
    return f'{URL_PREFIX}{value}' if URL_PREFIX else value

app.jinja_env.globals['relay_path']=relay_path

def csrf_token():
    token=session.get('_csrf_token')
    if not token:
        token=secrets.token_urlsafe(32)
        session['_csrf_token']=token
    return token

app.jinja_env.globals['csrf_token']=csrf_token

@app.before_request
def enforce_csrf():
    if not CSRF_ENABLED or request.method != 'POST' or request.path in {'/login','/sso'}:
        return None
    supplied=request.form.get('csrf_token') or request.headers.get('X-CSRF-Token') or ''
    expected=session.get('_csrf_token') or ''
    if not expected or not hmac.compare_digest(str(supplied),str(expected)):
        return jsonify(error='CSRF validation failed'), 400
    return None

def _token_part(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')

def _decode_token(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))

def issue_sso_token():
    payload=json.dumps({'exp':int(time.time())+60,'nonce':secrets.token_urlsafe(12)},separators=(',',':')).encode()
    encoded=_token_part(payload)
    signature=hmac.new(RELAY_SSO_SECRET.encode(),encoded.encode(),hashlib.sha256).digest()
    return encoded+'.'+_token_part(signature)

def verify_sso_token(token):
    try:
        encoded, signature=token.split('.',1)
        expected=_token_part(hmac.new(RELAY_SSO_SECRET.encode(),encoded.encode(),hashlib.sha256).digest())
        if not RELAY_SSO_SECRET or not hmac.compare_digest(signature,expected): return False
        payload=json.loads(_decode_token(encoded))
        return int(payload.get('exp',0)) >= int(time.time())
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        return False
def terminal_job(status): return status in TERMINAL_JOB_STATES
def active_job_id(jobs=JOBS):
    return next((job_id for job_id,job in jobs.items() if job.get('status')=='running'),None)
def job_snapshot(job):
    result=dict(job); total=result.get('total',0); done=result.get('done',0)
    result['percent']=100 if result.get('status')=='done' and total==0 else (round(done*100/total) if total else 0)
    return result
def should_commit_check_results(total, live_count, blocked_count=0):
    return total <= 1 or live_count > 0
def job_should_stop(job):
    return bool(job.get('stop_requested'))
def result_counts(rows):
    counts={'live':0,'live_verified':0,'live_unverified':0,'dead':0,'blocked':0,'inconclusive':0,'socks5':0,'http':0,'unknown':0}
    for row in rows:
        status=row.get('status','unknown'); proto=row.get('detected_protocol') or row.get('protocol') or 'unknown'
        if status=='live':
            counts['live'] += 1; counts['live_verified'] += 1
        elif status=='live_unverified':
            counts['live'] += 1; counts['live_unverified'] += 1
        else:
            counts[status if status in ('dead','blocked','inconclusive') else 'unknown'] += 1
        counts[proto if proto in ('socks5','http') else 'unknown'] += 1
    return counts

def apply_check_result(row,result):
    current_status=row.get('status') or 'unknown'
    current_streak=int(row.get('failure_streak') or 0)
    probe_status=result.get('status') or 'inconclusive'
    base={
        'last_check_status':probe_status,
        'latency_ms':result.get('latency_ms'),
        'error':result.get('error',''),
    }
    if probe_status in LIVE_STATUSES:
        return {**base,'status':probe_status,'detected_protocol':result.get('protocol') or 'unknown','exit_ip':result.get('exit_ip') or '','failure_streak':0}
    if probe_status=='blocked':
        return {**base,'status':'blocked','detected_protocol':result.get('protocol') or 'unknown','exit_ip':'','failure_streak':0}
    if current_status=='blocked':
        return {**base,'status':'blocked','detected_protocol':row.get('detected_protocol') or 'unknown','exit_ip':'','failure_streak':0}
    streak=current_streak+1
    if streak>=FAILURE_THRESHOLD:
        return {**base,'status':'dead','detected_protocol':'unknown','exit_ip':'','failure_streak':streak}
    if current_status in LIVE_STATUSES or current_status=='dead':
        return {**base,'status':current_status,'detected_protocol':row.get('detected_protocol') or 'unknown','exit_ip':row.get('exit_ip') or '','failure_streak':streak}
    return {**base,'status':'inconclusive','detected_protocol':row.get('detected_protocol') or 'unknown','exit_ip':row.get('exit_ip') or '','failure_streak':streak}
def proxy_counts(c):
    row=c.execute('''select count(*) total,
        sum(case when status in ('live','live_unverified') then 1 else 0 end) live,
        sum(case when status='live' then 1 else 0 end) live_verified,
        sum(case when status='live_unverified' then 1 else 0 end) live_unverified,
        sum(case when status='dead' then 1 else 0 end) dead,
        sum(case when status='blocked' then 1 else 0 end) blocked,
        sum(case when (status='inconclusive' or (last_check_status='inconclusive' and coalesce(failure_streak,0) < ?)) then 1 else 0 end) inconclusive,
        sum(case when status not in ('live','live_unverified','dead','blocked','inconclusive') or status is null then 1 else 0 end) unknown,
        sum(case when error is not null and trim(error)!='' then 1 else 0 end) error,
        sum(case when detected_protocol='socks5' then 1 else 0 end) socks5,
        sum(case when detected_protocol='http' then 1 else 0 end) http,
        sum(case when detected_protocol not in ('socks5','http') or detected_protocol is null then 1 else 0 end) unknown_protocol,
        count(distinct case when status in ('live','live_unverified') and exit_ip is not null and trim(exit_ip)!='' then exit_ip end) unique_exit
        from proxies''',(FAILURE_THRESHOLD,)).fetchone()
    return {key:int(row[key] or 0) for key in ('total','live','live_verified','live_unverified','dead','blocked','inconclusive','unknown','error','socks5','http','unknown_protocol','unique_exit')}
def build_proxy_filters(filters, public_ip=PUBLIC_IP):
    where=[]; params=[]
    q=(filters.get('q') or '').strip()
    if q:
        where.append('(host like ? or cast(port as text) like ? or exit_ip like ?)'); params += [f'%{q}%']*3
    upstream=(filters.get('upstream') or '').strip()
    if upstream:
        if ':' in upstream:
            host,port=upstream.rsplit(':',1)
            where.append('(host like ? and cast(port as text) like ?)'); params += [f'%{host}%',f'%{port}%']
        else:
            where.append('(host like ? or cast(port as text) like ?)'); params += [f'%{upstream}%']*2
    protocol=(filters.get('protocol') or '').strip().lower()
    if protocol:
        where.append("case when detected_protocol in ('http','socks5') then detected_protocol else 'unknown' end=?"); params.append(protocol)
    status=(filters.get('status') or '').strip().lower()
    if status:
        if status=='error': where.append("error is not null and trim(error)!=''")
        elif status=='usable': where.append("status in ('live','live_unverified')")
        elif status=='inconclusive': where.append("(status='inconclusive' or (last_check_status='inconclusive' and coalesce(failure_streak,0) < %d))" % FAILURE_THRESHOLD)
        else: where.append("coalesce(status,'unknown')=?"); params.append(status)
    exit_ip=(filters.get('exit_ip') or '').strip()
    if exit_ip: where.append('exit_ip like ?'); params.append(f'%{exit_ip}%')
    endpoint=(filters.get('endpoint') or '').strip()
    if endpoint:
        needle=endpoint
        if public_ip and needle.startswith(public_ip+':'): needle=needle[len(public_ip)+1:]
        port=needle.split(':',1)[0]
        where.append('(cast(http_port as text) like ? or cast(socks_port as text) like ?)'); params += [f'%{port}%']*2
    return ((' where '+' and '.join(where)) if where else ''),params
def pagination_window(page,total_pages,radius=2):
    if total_pages <= 0: return [1]
    pages=sorted(set([1,total_pages]+list(range(max(1,page-radius),min(total_pages,page+radius)+1))))
    result=[]
    for value in pages:
        if result and value-result[-1]>1: result.append(None)
        result.append(value)
    return result
def query_url(args,**changes):
    values={key:value for key,value in args.items() if value not in ('',None)}
    values.update({key:value for key,value in changes.items() if value not in ('',None)})
    return '?'+urlencode(values)
app.jinja_env.globals['query_url']=query_url
def bounded_int(value, default, minimum, maximum):
    try:
        parsed=int(value)
    except (TypeError,ValueError):
        parsed=default
    return min(maximum,max(minimum,parsed))
def selected_ids(values):
    return [int(v) for v in values if str(v).isdigit()]
def setting(c,key,default=''):
    row=c.execute('select value from settings where key=?',(key,)).fetchone(); return row['value'] if row else default
def reload_relay():
    c=conn(); rows=c.execute("select * from proxies where enabled=1 and status in ('live','live_unverified') and detected_protocol in ('http','socks5') order by id").fetchall(); data={'client_user':CLIENT_USER,'client_password':CLIENT_PASS,'entries':[{'id':r['id'],'port':client_port(r),'protocol':r['detected_protocol'],'host':r['host'],'upstream_port':r['port'],'username':r['username'],'password':r['password']} for r in rows]}; tmp=os.path.join(ROOT,'relay.json.tmp'); open(tmp,'w',encoding='utf8').write(json.dumps(data)); os.replace(tmp,os.path.join(ROOT,'relay.json')); subprocess.run(['systemctl','kill','-s','HUP','proxy-relay-engine'],capture_output=True,check=False)
def run_check_ids(ids=None, concurrency=32, job_id=None):
    c=conn(); query='select * from proxies where enabled=1'; params=[]
    if ids is not None: query += ' and id in (%s)'%(','.join('?'*len(ids)) if ids else '0'); params=ids
    rows=c.execute(query,params).fetchall(); c.close()
    with ThreadPoolExecutor(max_workers=max(1,min(100,concurrency))) as pool:
        futures={pool.submit(check_proxy,dict(r)):r['id'] for r in rows}; results=[]
        for f in as_completed(futures):
            if job_id:
                with JOB_LOCK: stopped=job_should_stop(JOBS.get(job_id,{}))
                if stopped:
                    for pending in futures:
                        pending.cancel()
                    break
            try: result=f.result()
            except Exception as exc: result={'status':'inconclusive','protocol':'unknown','exit_ip':'','latency_ms':None,'error':str(exc)[-500:]}
            results.append((futures[f],result))
            if job_id:
                with JOB_LOCK:
                    job=JOBS[job_id]
                    job.setdefault('row_results',{})[futures[f]]=dict(result)
                    job.update(done=len(results),**result_counts([x[1] for x in results]))
    live_count=sum(1 for _,result in results if is_usable_status(result['status']))
    blocked_count=sum(1 for _,result in results if result['status']=='blocked')
    c=conn(); operational_changed=False
    rows_by_id={row['id']:dict(row) for row in rows}
    for pid,result in results:
        updates=apply_check_result(rows_by_id[pid],result)
        previous=rows_by_id[pid]
        if updates['status'] != previous.get('status') or updates['detected_protocol'] != (previous.get('detected_protocol') or 'unknown') or updates['exit_ip'] != (previous.get('exit_ip') or ''):
            operational_changed=True
        c.execute('''update proxies set status=?,detected_protocol=?,exit_ip=?,latency_ms=?,error=?,
            checked_at=current_timestamp,last_check_status=?,failure_streak=? where id=?''',
            (updates['status'],updates['detected_protocol'],updates['exit_ip'],updates['latency_ms'],updates['error'],updates['last_check_status'],updates['failure_streak'],pid))
    c.commit()
    if results and operational_changed: reload_relay()
    if job_id and results and not live_count:
        message='All checks hit a provider captive portal; blocked results were recorded.' if blocked_count==len(results) and results else 'No proxy reached Live quorum; transient results were recorded without immediately closing existing listeners.'
        with JOB_LOCK: JOBS[job_id].update(status='warning',error=message)
    if job_id:
        with JOB_LOCK:
            if JOBS[job_id].get('stop_requested'): JOBS[job_id].update(status='stopped')
            elif JOBS[job_id].get('status') != 'warning': JOBS[job_id].update(status='done')
            JOBS[job_id].update(done=len(results))
def start_check(ids, concurrency):
    if not ids: return ''
    with JOB_LOCK:
        current=active_job_id()
        if current: return current
    job_id=uuid.uuid4().hex
    with JOB_LOCK: JOBS[job_id]={'status':'running','total':len(ids),'done':0,'live':0,'live_verified':0,'live_unverified':0,'dead':0,'blocked':0,'inconclusive':0,'socks5':0,'http':0,'unknown':0,'ids':list(ids)}
    threading.Thread(target=run_check_ids,args=(ids,concurrency,job_id),daemon=True).start()
    return job_id
def login_required(fn):
    @wraps(fn)
    def inner(*a,**kw):
        if not session.get('admin'): return redirect(relay_path('/login'))
        return fn(*a,**kw)
    return inner
@app.route('/login',methods=['GET','POST'])
def login():
    ip=login_client_ip(); locked,retry_after=login_guard_state(ip)
    if request.method=='POST':
        if locked:
            return render_template('login.html',login_error=f'Too many failed attempts. Try again in {retry_after} seconds.'),429,{'Retry-After':str(retry_after)}
        valid=secrets.compare_digest(request.form.get('username',''),ADMIN_USER) and secrets.compare_digest(request.form.get('password',''),ADMIN_PASS)
        if valid:
            clear_login_failures(ip); session['admin']=True; return redirect(relay_path('/'))
        failures=record_login_failure(ip); locked,retry_after=login_guard_state(ip)
        if locked:
            return render_template('login.html',login_error=f'Too many failed attempts. Try again in {retry_after} seconds.'),429,{'Retry-After':str(retry_after)}
        return render_template('login.html',login_error=f'Invalid username or password. {LOGIN_MAX_FAILURES-failures} attempt(s) remaining.'),401
    return render_template('login.html',login_error='')
@app.route('/logout')
def logout(): session.clear(); return redirect(relay_path('/login'))

@app.route('/sso', methods=['POST'])
def sso():
    if not verify_sso_token(str(request.form.get('token') or '')):
        return render_template('login.html', login_error='The admin handoff expired. Start again from Earn Proxy.'), 401
    session['admin']=True
    session['_csrf_token']=secrets.token_urlsafe(32)
    return redirect(relay_path('/'))
@app.route('/healthz')
def healthz():
    try:
        c=conn(); c.execute('select 1').fetchone(); c.close()
        return {'status':'ok'}
    except Exception:
        return {'status':'error'},503

@app.route('/internal/feed')
def internal_feed():
    remote=(request.remote_addr or '').strip()
    supplied=request.headers.get('X-Relay-Feed-Key','')
    if remote not in {'127.0.0.1','::1'} or not RELAY_FEED_KEY or not hmac.compare_digest(supplied, RELAY_FEED_KEY):
        return jsonify(error='Unauthorized'), 401
    c=conn()
    rows=c.execute("select * from proxies where enabled=1 and status in ('live','live_unverified') and detected_protocol in ('http','socks5') order by id").fetchall()
    items=[{'proxy':format_endpoint(row,row['detected_protocol']), 'protocol':row['detected_protocol'], 'exit_ip':row['exit_ip'] or ''} for row in rows]
    c.close()
    response=jsonify(items=items)
    response.headers['Cache-Control']='no-store'
    return response
@app.route('/')
@login_required
def index():
    c=conn(); filters={key:request.args.get(key,'').strip() for key in ('q','upstream','protocol','endpoint','status','exit_ip')}; page=bounded_int(request.args.get('page','1'),1,1,1000000000); per_page=bounded_int(request.args.get('per_page','25'),25,10,250); clause,params=build_proxy_filters(filters); filtered_total=c.execute('select count(*) from proxies'+clause,params).fetchone()[0]; total_pages=max(1,(filtered_total+per_page-1)//per_page); page=min(page,total_pages); proxies=c.execute('select * from proxies'+clause+' order by id limit ? offset ?',params+[per_page,(page-1)*per_page]).fetchall(); counts=proxy_counts(c); first_record=(page-1)*per_page+1 if filtered_total else 0; last_record=min(page*per_page,filtered_total)
    undo_batch=latest_undo_batch(c)
    return render_template('index.html',proxies=proxies,counts=counts,filtered_total=filtered_total,page=page,total_pages=total_pages,page_window=pagination_window(page,total_pages),first_record=first_record,last_record=last_record,per_page=per_page,filters=filters,client_user=CLIENT_USER,client_pass=CLIENT_PASS,public_ip=PUBLIC_IP,check_concurrency=setting(c,'check_concurrency','32'),job_id=request.args.get('job',''),undo_batch=undo_batch)
@app.route('/duplicates')
@login_required
def duplicates():
    c=conn(); q=request.args.get('q','').strip(); min_count=bounded_int(request.args.get('min_count','2'),2,2,1000000000); page=bounded_int(request.args.get('page','1'),1,1,1000000000); per_page=bounded_int(request.args.get('per_page','25'),25,10,250); groups=c.execute("select exit_ip,count(*) n from proxies where status in ('live','live_unverified') and exit_ip is not null and exit_ip!='' group by exit_ip having count(*)>=? order by n desc,exit_ip",(min_count,)).fetchall(); groups=[g for g in groups if not q or q.lower() in g['exit_ip'].lower()]; total=len(groups); total_pages=max(1,(total+per_page-1)//per_page); page=min(page,total_pages); shown=groups[(page-1)*per_page:page*per_page]; rows=[]
    for group in shown: rows.extend(c.execute("select * from proxies where status in ('live','live_unverified') and exit_ip=? order by id",(group['exit_ip'],)).fetchall())
    return render_template('duplicates.html',groups=shown,total=total,page=page,total_pages=total_pages,page_window=pagination_window(page,total_pages),first_record=((page-1)*per_page+1 if total else 0),last_record=min(page*per_page,total),per_page=per_page,q=q,min_count=min_count,proxies=rows,public_ip=PUBLIC_IP,client_user=CLIENT_USER,client_pass=CLIENT_PASS)
@app.route('/import',methods=['POST'])
@login_required
def import_proxy():
    c=conn(); added=0; duplicates=0; errors=[]; ids=[]; lines=request.form.get('lines','').splitlines()
    batch_id=c.execute('insert into import_batches(input_count) values(?)',(len(lines),)).lastrowid
    for line in lines:
        try:
            p=parse_proxy_line(line); existing=c.execute('select id from proxies where host=? and port=? and username=? and password=?',(p['host'],p['port'],p['username'],p['password'])).fetchone()
            if existing: duplicates+=1; continue
            hp,sp=next_ports(c); cur=c.execute('insert into proxies(host,port,username,password,protocol,http_port,socks_port,import_batch_id) values(?,?,?,?,?,?,?,?)',(p['host'],p['port'],p['username'],p['password'],p['protocol'],hp,sp,batch_id)); ids.append(cur.lastrowid); added+=1
        except Exception as e: errors.append(f'{line}: {e}')
    c.execute('update import_batches set added_count=?,duplicate_count=?,error_count=? where id=?',(added,duplicates,len(errors),batch_id))
    c.commit(); flash(f'Imported {added} proxy(s), skipped {duplicates} duplicate(s). '+('Errors: '+' | '.join(errors) if errors else '')); return redirect(relay_path('/'))

@app.route('/import/undo',methods=['POST'])
@login_required
def undo_import():
    with JOB_LOCK:
        if active_job_id():
            flash('Cannot undo an import while a proxy check is running. Stop or wait for the check to finish.')
            return redirect(relay_path('/'))
        c=conn(); batch=latest_undo_batch(c)
        if not batch:
            c.close(); flash('There is no import batch available to undo.'); return redirect(relay_path('/'))
        try:
            c.execute('begin immediate')
            rows=c.execute('select id from proxies where import_batch_id=?',(batch['id'],)).fetchall()
            c.execute('delete from proxies where import_batch_id=?',(batch['id'],))
            c.execute('update import_batches set undone_at=current_timestamp,undone_count=? where id=?',(len(rows),batch['id']))
            c.commit()
        except Exception:
            c.rollback(); c.close(); raise
        c.close()
    reload_relay()
    flash(f'Undid import batch #{batch["id"]}: removed {len(rows)} proxy(s). Existing and duplicate proxies were preserved.')
    return redirect(relay_path('/'))
@app.route('/check/<int:pid>',methods=['POST'])
@login_required
def check(pid):
    job_id=start_check([pid],int(setting(conn(),'check_concurrency','32'))); return redirect(relay_path('/')+'?job='+job_id)
@app.route('/batch',methods=['POST'])
@login_required
def batch():
    ids=selected_ids(request.form.getlist('selected')); action=request.form.get('action')
    c=conn(); concurrency=int(setting(c,'check_concurrency','32'))
    job_id=''
    if action=='check' and ids: job_id=start_check(ids,concurrency)
    elif action in ('check_all','check_unchecked','check_dead'):
        query='select id from proxies'; params=[]
        if action=='check_unchecked': query += ' where checked_at is null'
        elif action=='check_dead': query += " where status='dead'"
        job_id=start_check([r['id'] for r in c.execute(query,params).fetchall()],concurrency)
    elif action=='delete' and ids:
        c=conn(); c.executemany('delete from proxies where id=?',[(i,) for i in ids]); c.commit(); reload_relay()
    elif action=='delete_all':
        c=conn(); c.execute('delete from proxies'); c.commit(); reload_relay()
    return redirect(relay_path('/')+'?job='+job_id if job_id else relay_path('/'))
@app.route('/job/<job_id>')
@login_required
def job(job_id):
    with JOB_LOCK: return job_snapshot(JOBS.get(job_id,{'status':'missing','total':0,'done':0}))
@app.route('/job/<job_id>/rows')
@login_required
def job_rows(job_id):
    with JOB_LOCK: job=JOBS.get(job_id)
    if not job: return {'rows':[]}
    ids=job.get('ids',[])
    c=conn(); rows=c.execute('select id,status,last_check_status,failure_streak,detected_protocol,exit_ip from proxies where id in (%s)'%(','.join('?'*len(ids)) if ids else '0'),ids).fetchall() if ids else []
    result_by_id=job.get('row_results',{})
    payload=[]
    for row in rows:
        result=dict(row); result.update({key:value for key,value in result_by_id.get(row['id'],{}).items() if key in ('status','protocol','exit_ip','last_check_status','failure_streak')})
        if 'protocol' in result:
            result['detected_protocol']=result.pop('protocol')
        payload.append(result)
    return {'rows':payload}
@app.route('/job/<job_id>/stop',methods=['POST'])
@login_required
def stop_job(job_id):
    with JOB_LOCK:
        if job_id in JOBS and JOBS[job_id].get('status')=='running': JOBS[job_id]['stop_requested']=True
    return redirect(relay_path('/')+'?job='+job_id)
@app.route('/settings',methods=['POST'])
@login_required
def settings():
    concurrency=str(bounded_int(request.form.get('check_concurrency','32'),32,1,100)); c=conn(); c.execute("insert or replace into settings values('check_concurrency',?)",(concurrency,)); c.commit(); flash('Manual check concurrency saved.'); return redirect(relay_path('/'))
@app.route('/delete/<int:pid>',methods=['POST'])
@login_required
def delete(pid):
    c=conn(); c.execute('delete from proxies where id=?',(pid,)); c.commit(); reload_relay(); return redirect(relay_path('/'))
@app.route('/export/<fmt>')
@login_required
def export(fmt):
    ids=selected_ids(request.args.getlist('id')); c=conn(); query='select * from proxies where enabled=1'; params=[]
    if ids: query += ' and id in (%s)'%','.join('?'*len(ids)); params=ids
    rows=c.execute(query+' order by id',params).fetchall(); out=io.StringIO(); protocol=request.args.get('protocol','both'); unique=request.args.get('unique')=='1'
    if unique: rows=unique_exit_rows(rows)
    if fmt=='csv':
        w=csv.writer(out); w.writerow(['proxy','protocol','status','exit_ip']); [w.writerow([format_endpoint(r,r['detected_protocol']),r['detected_protocol'],r['status'],r['exit_ip']]) for r in rows if is_usable_status(r['status'])]; mime='text/csv'
    else:
        values=[]
        for r in rows:
            if is_usable_status(r['status']) and (protocol=='both' or protocol==r['detected_protocol']): values.append(format_endpoint(r,r['detected_protocol']))
        out.write('\n'.join(values)); mime='text/plain'
    return Response(out.getvalue(),mimetype=mime,headers={'Content-Disposition':f'attachment; filename=proxies.{fmt}'})
@app.route('/duplicates/export/raw')
@login_required
def export_duplicate_raw():
    c=conn()
    rows=c.execute("select p.*,d.duplicate_count from proxies p join (select exit_ip,count(*) duplicate_count from proxies where status in ('live','live_unverified') and exit_ip is not null and exit_ip!='' group by exit_ip having count(*)>1) d on d.exit_ip=p.exit_ip where p.status in ('live','live_unverified') order by p.exit_ip,p.id").fetchall()
    return Response(duplicate_raw_csv(rows),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=provider-duplicate-exit-groups.csv'})
if __name__=='__main__':
    conn(); reload_relay()
    web_host,web_port=web_bind()
    app.run(host=web_host,port=web_port)
