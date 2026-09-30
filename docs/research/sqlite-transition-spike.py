"""Disposable SQL hypothesis check, NOT a Rodauth/Sequel or multi-DB proof.
Run: python3 docs/research/sqlite-transition-spike.py
"""
import concurrent.futures
import json
import sqlite3
import tempfile
import threading
import time
from pathlib import Path


def connect(path):
    db = sqlite3.connect(path, timeout=1, isolation_level=None)
    return db


def setup(path, status='approved', expires=None):
    db = connect(path)
    db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE requests(id INTEGER PRIMARY KEY, client TEXT NOT NULL,
          status TEXT NOT NULL, version INTEGER NOT NULL, expires REAL NOT NULL);
        CREATE TABLE grants(id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL);
    ''')
    db.execute('INSERT INTO requests VALUES(1,?,?,0,?)',
               ('client-a', status, expires if expires is not None else time.time()+60))
    db.close()


def transition(path, expected, target, barrier=None, fail=False, client='client-a'):
    db = connect(path)
    if barrier:
        barrier.wait(timeout=5)
    try:
        for attempt in range(20):
            try:
                db.execute('BEGIN')
                row = db.execute('SELECT status,version FROM requests WHERE id=1').fetchone()
                if row[0] != expected:
                    db.rollback()
                    return False
                count = db.execute('''UPDATE requests SET version=version+1
                    WHERE id=1 AND client=? AND status=? AND version=? AND expires>?''',
                    (client, expected, row[1], time.time())).rowcount
                if count != 1:
                    db.rollback()
                    return False
                expires = db.execute('SELECT expires FROM requests WHERE id=1').fetchone()[0]
                if expires <= time.time():
                    db.rollback()
                    return False
                db.execute('UPDATE requests SET status=? WHERE id=1', (target,))
                if target == 'consumed':
                    db.execute('INSERT INTO grants(request_id) VALUES(1)')
                if fail:
                    raise RuntimeError('simulated transaction hook failure')
                db.commit()
                return True
            except sqlite3.OperationalError as exc:
                db.rollback()
                if 'locked' not in str(exc).lower():
                    raise
                time.sleep(0.002 * (attempt+1))
            except Exception:
                db.rollback()
                raise
        raise RuntimeError('bounded retry exhausted')
    finally:
        db.close()


def inspect(path):
    db = connect(path)
    result = (db.execute('SELECT status,version FROM requests').fetchone(),
              db.execute('SELECT count(*) FROM grants').fetchone()[0])
    db.close()
    return result


def run():
    checks = []
    with tempfile.TemporaryDirectory(prefix='ciba-sql-spike-') as tmp:
        root = Path(tmp)
        for name, initial, targets in [
            ('double_poll', 'approved', ('consumed','consumed')),
            ('approve_deny_race', 'pending', ('approved','denied')),
        ]:
            for n in range(20):
                path=root/f'{name}-{n}.sqlite'
                setup(path, initial)
                barrier=threading.Barrier(2)
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    futures=[pool.submit(transition,path,initial,t,barrier) for t in targets]
                    results=[f.result(timeout=10) for f in futures]
                assert sum(results)==1, (name, results)
                row, grants=inspect(path)
                assert row[1]==1
                assert grants==(1 if name=='double_poll' else 0)
            checks.append({'case':name,'repetitions':20,'passed':True})
        path=root/'rollback.sqlite'
        setup(path)
        try:
            transition(path,'approved','consumed',fail=True)
            raise AssertionError('expected hook failure')
        except RuntimeError as exc:
            assert str(exc)=='simulated transaction hook failure'
        assert inspect(path)==(('approved',0),0)
        assert transition(path,'approved','consumed')
        assert not transition(path,'approved','consumed')
        assert inspect(path)==(('consumed',1),1)
        checks.append({'case':'rollback_then_retry_and_replay','passed':True})
        for name, expiry, client in [('expired',0,'client-a'),('other_client',None,'client-b')]:
            path=root/f'{name}.sqlite'
            setup(path,expires=expiry)
            assert not transition(path,'approved','consumed',client=client)
            assert inspect(path)==(('approved',0),0)
            checks.append({'case':name,'passed':True})
    return {'engine':'SQLite','version':sqlite3.sqlite_version,'checks':checks,
            'limits':['Python sqlite3, not Sequel/Rodauth','No PostgreSQL/MySQL proof',
                      'No JWT/token HTTP integration','No after-commit callback proof']}

if __name__=='__main__':
    result=run()
    output=Path(__file__).with_name('sqlite-transition-spike-result.json')
    output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
