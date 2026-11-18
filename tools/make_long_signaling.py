"""Generate bounded-memory long-connection regressions; all identities and keys are synthetic."""
from pathlib import Path
import socket, ssl, struct, sys, tempfile

ROOT = Path(__file__).resolve().parents[1]
COUNT = 35010

def packet(payload, protocol=6, reverse=False, sequence=1001, ports=None):
    source, target = ('198.18.0.2', '198.18.0.1') if reverse else ('198.18.0.1', '198.18.0.2')
    sp, dp = ports or ((5061, 18000) if reverse else (18000, 5061))
    transport = struct.pack('!HHIIBBHHH', sp, dp, sequence, 0, 0x50, 0x18, 65535, 0, 0) if protocol == 6 else struct.pack('!HHHH', sp, dp, len(payload)+8, 0)
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(transport)+len(payload), 1, 0, 64, protocol, 0, socket.inet_aton(source), socket.inet_aton(target))+transport+payload

def message(index):
    tail = index >= COUNT-3
    method = ['INVITE', 'INFO', 'BYE'][index-(COUNT-3)] if tail else 'OPTIONS'
    body = b'Signal=9\r\nDuration=120\r\n' if method == 'INFO' else b'v=0\r\nc=IN IP4 198.18.0.1\r\nm=audio 7000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n' if method == 'INVITE' else b''
    content = 'application/dtmf-relay' if method == 'INFO' else 'application/sdp'
    call = 'late-call@merged.invalid' if tail else f'background-{index//10}@merged.invalid'
    return (f'{method} sip:1002@merged.invalid SIP/2.0\r\nVia: SIP/2.0/TCP 198.18.0.1:18000;branch=z9hG4bK-{index}\r\n'
            f'From: <sip:1001@merged.invalid>;tag=caller\r\nTo: <sip:1002@merged.invalid>\r\nCall-ID: {call}\r\nCSeq: {index+1} {method}\r\n'
            f'X-Regression-Index: {index}\r\nX-Padding: '+('x'*720)+f'\r\nContent-Type: {content}\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body

def frame(payload):
    return b'\x81\x7e'+struct.pack('!H', len(payload))+payload

def generate(folder, kind):
    path = folder / (kind+'.pcap')
    with path.open('wb') as out, tempfile.TemporaryDirectory() as temporary:
        out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        seq = [1001, 9001]
        def record(data, reverse=False, tick=0, protocol=6, ports=None):
            p = packet(data, protocol, reverse, seq[int(reverse)], ports)
            t = 1794970000000000+tick
            out.write(struct.pack('<IIII', t//1000000, t%1000000, len(p), len(p)));out.write(p)
            if protocol == 6: seq[int(reverse)] += len(data)
        if kind == 'udp':
            for i in range(COUNT):record(message(i), tick=10000000+i*200000, protocol=17)
        elif kind == 'tcp':
            for i in range(COUNT):
                data=message(i);cut=83 if i%97==0 else len(data)
                record(data[:cut], tick=10000000+i*200000)
                if cut<len(data):record(data[cut:], tick=10000001+i*200000)
        else:
            websocket = kind == 'tls13-wss'
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client.check_hostname=False;client.verify_mode=ssl.CERT_NONE
            version=ssl.TLSVersion.TLSv1_3 if websocket else ssl.TLSVersion.TLSv1_2
            for ctx in (client,server):ctx.minimum_version=ctx.maximum_version=version;ctx.set_ciphers('AES128-GCM-SHA256:@SECLEVEL=0')
            server.load_cert_chain(ROOT/'tests/fixtures/rsa-synthetic-certificate.pem', ROOT/'tests/fixtures/rsa-synthetic-pkcs8.key')
            log=Path(temporary)/'public-synthetic.keys';client.keylog_filename=str(log)
            ci,co,si,so=[ssl.MemoryBIO() for _ in range(4)]
            c=client.wrap_bio(ci,co,server_side=False,server_hostname='merged.invalid');s=server.wrap_bio(si,so,server_side=True)
            def transfer(reverse, tick):
                source,target=(so,ci) if reverse else (co,si);data=source.read()
                if data:
                    target.write(data)
                    for offset in range(0,len(data),1400):record(data[offset:offset+1400],reverse,tick+offset)
            done=[False,False]
            for step in range(100):
                for n,connection in enumerate((c,s)):
                    try:connection.do_handshake();done[n]=True
                    except ssl.SSLWantReadError:pass
                    transfer(bool(n),step*10000+n*3000)
                if all(done):break
            assert all(done)
            def send(payload,tick,reverse=False):
                sender,receiver=(s,c) if reverse else (c,s);sender.write(payload);transfer(reverse,tick)
                try:receiver.read(65536)
                except ssl.SSLWantReadError:pass
                transfer(not reverse,tick+3000)
            if websocket:
                send(b'GET /sip HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',1000000)
                send(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',2000000,True)
            for i in range(COUNT):send(frame(message(i)) if websocket else message(i),10000000+i*200000)
            client.keylog_filename=None
            (folder/(kind+'.keys')).write_bytes(log.read_bytes())
        # Media near the final call must survive indexing after hours of background signaling.
        for i in range(10):
            payload=struct.pack('!BBHII',0x80,8,i,i*160,0x12345678)+b'\xd5'*160
            record(payload,tick=10000000+(COUNT-3)*200000+i*20000,protocol=17,ports=(7000,7002))
    print(f'Generated {kind}: {COUNT} SIP messages, {path.stat().st_size} bytes', flush=True)

if __name__=='__main__':
    folder=Path(sys.argv[1]);folder.mkdir(parents=True,exist_ok=True)
    for kind in ('udp','tcp','tls12-rsa','tls13-wss'):generate(folder,kind)
