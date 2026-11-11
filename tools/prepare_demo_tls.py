"""Optional creation of public TLS demo sessions using existing synthetic test keys.

No real credentials are read. Normal builds consume the saved, offline inputs.
"""
from pathlib import Path
import ssl, tempfile
from make_demo_capture import ROOT, INPUT, FIXTURES, calls, pcap, tcp, ws

def main():
    INPUT.mkdir(parents=True,exist_ok=True);combined=[]
    for call in calls()[-2:]:
        websocket=call.number==23;call.transport='WSS' if websocket else 'TLS'
        with tempfile.TemporaryDirectory() as temporary:
            log=Path(temporary)/'synthetic.keys'
            server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client.check_hostname=False;client.verify_mode=ssl.CERT_NONE
            version=ssl.TLSVersion.TLSv1_3 if websocket else ssl.TLSVersion.TLSv1_2
            for ctx in (client,server):ctx.minimum_version=ctx.maximum_version=version;ctx.set_ciphers('AES128-GCM-SHA256:@SECLEVEL=0')
            server.load_cert_chain(FIXTURES/'rsa-synthetic-certificate.pem',FIXTURES/'rsa-synthetic-pkcs8.key');client.keylog_filename=str(log)
            ci,co,si,so=[ssl.MemoryBIO() for _ in range(4)]
            c=client.wrap_bio(ci,co,server_side=False,server_hostname='synthetic.example.test');s=server.wrap_bio(si,so,server_side=True)
            records=[];sequence=[1001,9001];done=[False,False]
            def transfer(reverse,at):
                source,destination=(so,ci) if reverse else (co,si);data=source.read()
                if not data:return
                destination.write(data);src,dst=(call.b,call.a) if reverse else (call.a,call.b)
                client_port=18000+call.number;server_port=443 if websocket else 5061
                sp,dp=(server_port,client_port) if reverse else (client_port,server_port)
                for offset in range(0,len(data),211):
                    part=data[offset:offset+211];records.append((call.start+at+offset,tcp(part,src,dst,sp,dp,sequence[int(reverse)])));sequence[int(reverse)]+=len(part)
            for attempt in range(100):
                for index,connection in enumerate((c,s)):
                    try:connection.do_handshake();done[index]=True
                    except ssl.SSLWantReadError:pass
                    transfer(bool(index),attempt*3000+index*1000)
                if all(done):break
            assert all(done)
            def send(reverse,at,payload):
                sender,receiver=(s,c) if reverse else (c,s);sender.write(payload);transfer(reverse,at)
                try:receiver.read(1048576)
                except ssl.SSLWantReadError:pass
                transfer(not reverse,at+500)
            if websocket:
                send(False,20000,b'GET /sip HTTP/1.1\r\nHost: demo.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ZGVtby1odWF0YW4tMjAyNg==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n\r\n')
                send(True,30000,b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: sip\r\n\r\n')
            plain=[]
            call.wire=lambda at,payload,reverse=False:plain.append((at,reverse,payload))
            call.connect();call.finish(reverse=websocket)
            for at,reverse,message in plain:send(reverse,at+40000,ws(message,not reverse) if websocket else message)
            (INPUT/('wss.pcap' if websocket else 'tls-rsa.pcap')).write_bytes(pcap(records))
            if websocket:combined.append(log.read_bytes())
            client.keylog_filename=None
    (INPUT/'demo-tls.keys').write_bytes(b'# PUBLIC SYNTHETIC DEMO SESSIONS ONLY\n'+b'\n'.join(combined))
    (INPUT/'demo-rsa.key').write_bytes((FIXTURES/'rsa-synthetic-pkcs8.key').read_bytes())
    print('Prepared two synthetic TLS conversations; test-only key material saved locally')

if __name__=='__main__':main()
