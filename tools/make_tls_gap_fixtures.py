"""Public synthetic TLS sessions split into an early handshake and a later call."""
from pathlib import Path
import ssl, struct, sys, tempfile
from make_long_signaling import ROOT, packet

TARGET = 'late-call@split.invalid'

def sip(method, call=TARGET, body=b'', sequence=100, reverse=False):
    first = 'SIP/2.0 200 OK' if reverse else f'{method} sip:1002@split.invalid SIP/2.0'
    content = 'application/dtmf-relay' if method == 'INFO' else 'application/sdp'
    return (f'{first}\r\nVia: SIP/2.0/TLS 198.18.0.1:18000;branch=z9hG4bK-{sequence}\r\n'
            f'From: <sip:1001@split.invalid>;tag=a\r\nTo: <sip:1002@split.invalid>;tag=b\r\n'
            f'Call-ID: {call}\r\nCSeq: {sequence} {method}\r\nContent-Type: {content}\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body

def save(path, rows):
    with path.open('wb') as out:
        out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        for tick, data in sorted(rows, key=lambda x:x[0]):
            t=1794963616000000+tick
            out.write(struct.pack('<IIII',t//1000000,t%1000000,len(data),len(data)));out.write(data)

def generate(folder, name, cipher, version=ssl.TLSVersion.TLSv1_2):
    rows=[];late=[];seq=[1001,9001]
    with tempfile.TemporaryDirectory() as temporary:
        server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.check_hostname=False;client.verify_mode=ssl.CERT_NONE
        for ctx in (client,server):ctx.minimum_version=ctx.maximum_version=version;ctx.set_ciphers(cipher+':@SECLEVEL=0')
        server.load_cert_chain(ROOT/'tests/fixtures/rsa-synthetic-certificate.pem',ROOT/'tests/fixtures/rsa-synthetic-pkcs8.key')
        log=Path(temporary)/'synthetic.keys';client.keylog_filename=str(log)
        ci,co,si,so=[ssl.MemoryBIO() for _ in range(4)]
        c=client.wrap_bio(ci,co,server_side=False,server_hostname='split.invalid');s=server.wrap_bio(si,so,server_side=True)
        def transfer(reverse,tick,keep=True):
            source,destination=(so,ci) if reverse else (co,si);data=source.read()
            if not data:return
            destination.write(data)
            for offset in range(0,len(data),1400):
                part=data[offset:offset+1400]
                if keep:
                    row=(tick+offset,packet(part,reverse=reverse,sequence=seq[int(reverse)]))
                    rows.append(row)
                    if tick>=9000000000:late.append(len(rows)-1)
                seq[int(reverse)]+=len(part)
        done=[False,False]
        for step in range(100):
            for n,connection in enumerate((c,s)):
                try:connection.do_handshake();done[n]=True
                except ssl.SSLWantReadError:pass
                transfer(bool(n),step*10000+n*3000)
            if all(done):break
        assert all(done)
        def send(payload,tick,reverse=False,keep=True):
            sender,receiver=(s,c) if reverse else (c,s);sender.write(payload);transfer(reverse,tick,keep)
            try:receiver.read(65536)
            except ssl.SSLWantReadError:pass
            transfer(not reverse,tick+2000,keep)
        send(sip('OPTIONS','early@split.invalid',sequence=1),1000000)
        send(sip('OPTIONS','early@split.invalid',sequence=1,reverse=True),2000000,True)
        # The first segment ends partway through a SIP body. It must not be joined to the later segment.
        send(b'MESSAGE sip:1002@split.invalid SIP/2.0\r\nCall-ID: incomplete@split.invalid\r\nCSeq: 2 MESSAGE\r\nContent-Length: 999999\r\n\r\npartial',3000000)
        count=55000 if name=='gcm256' else 19
        for i in range(count):send(b'missing client data',4000000,keep=False)
        for i in range(count*2):send(b'missing server data',4000000,reverse=True,keep=False)
        # The later segment itself starts in the middle of another SIP body.
        send(b'continuation of an uncaptured SIP body\r\n',9000000000)
        caller=b'v=0\r\nc=IN IP4 198.18.0.1\r\nm=audio 7000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n'
        callee=caller.replace(b'198.18.0.1',b'198.18.0.2').replace(b'7000',b'7002')
        send(sip('INVITE',body=caller),9001000000)
        send(sip('INVITE',body=callee,reverse=True),9002000000,True)
        send(sip('ACK'),9003000000)
        send(sip('INFO',body=b'Signal=7\r\nDuration=160\r\n',sequence=101),9004000000)
        send(sip('BYE',sequence=102),9005000000)
        send(sip('BYE',sequence=102,reverse=True),9006000000,True)
        client.keylog_filename=None
        (folder/(name+'.keys')).write_bytes(log.read_bytes())
    for reverse in (False,True):
        for i in range(10):
            payload=struct.pack('!BBHII',0x80,0,i,i*160,0x12345678+int(reverse))+b'\xff'*160
            rows.append((9002100000+i*20000,packet(payload,protocol=17,reverse=reverse,ports=(7002,7000) if reverse else (7000,7002))))
    save(folder/(name+'.pcap'),rows)
    if name=='gcm256':
        first=late[0];tick,data=rows[first]
        # Cut off the TLS header and part of the first encrypted record, preserving TCP sequence numbers.
        cut=17;trimmed=bytearray(data[:40]+data[40+cut:]);trimmed[2:4]=struct.pack('!H',len(trimmed));trimmed[24:28]=struct.pack('!I',int.from_bytes(data[24:28],'big')+cut)
        clipped=list(rows);clipped[first]=(tick,bytes(trimmed));save(folder/'gcm256-mid-record.pcap',clipped)
        tampered=list(rows);corrupt=bytearray(data);corrupt[-1]^=1;tampered[first]=(tick,bytes(corrupt));save(folder/'gcm256-tampered.pcap',tampered)
        save(folder/'gcm256-no-handshake.pcap',[r for r in rows if r[0]>=9000000000])
        save(folder/'gcm256-handshake-only.pcap',[r for r in rows if r[0]<1000000 or r[0]>=9000000000])
    print(f'Generated TLS gap case {name}: omitted {count} client / {count*2} server records; public synthetic keys only',flush=True)

if __name__=='__main__':
    folder=Path(sys.argv[1]);folder.mkdir(parents=True,exist_ok=True)
    generate(folder,'gcm256','AES256-GCM-SHA384')
    generate(folder,'gcm128','AES128-GCM-SHA256')
    generate(folder,'cbc','AES128-SHA')
    generate(folder,'tls13','AES128-GCM-SHA256',ssl.TLSVersion.TLSv1_3)
