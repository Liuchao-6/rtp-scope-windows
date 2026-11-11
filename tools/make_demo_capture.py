"""Build the same multi-call, synthetic-only showcase for Android and Windows.

Saved codec/TLS inputs make normal generation deterministic and entirely offline.
The older single-call test fixtures remain independent regression inputs.
"""
from pathlib import Path
import audioop, hashlib, json, math, socket, struct

ROOT=Path(__file__).resolve().parents[1]
FIXTURES=ROOT/'tests/fixtures'
INPUT=FIXTURES/'demo-audio'
EPOCH=1794358800000000  # 2026-11-11 09:00:00 Asia/Shanghai
CODECS={'PCMU':(0,8000),'PCMA':(8,8000),'G729':(18,8000),'G729A':(96,8000),'OPUS':(111,48000),'G722':(9,8000),'AMR':(112,8000),'AMR-WB':(113,16000)}
KEYS='0123456789*#ABCD'
NB_BITS=[95,103,118,134,148,159,204,244,39,-1,-1,-1,-1,-1,0]
WB_BITS=[132,177,253,285,317,365,397,461,477,40,-1,-1,-1,-1,0,0]

def checksum(data):
    data+=b'\0'*(len(data)%2);value=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while value>>16:value=(value&65535)+(value>>16)
    return (~value)&65535

def ip(body,src,dst,protocol=17):
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(body),0,0,64,protocol,0,socket.inet_aton(src),socket.inet_aton(dst))
    return header[:10]+struct.pack('!H',checksum(header))+header[12:]+body

def udp(body,src,dst,sp,dp):
    return ip(struct.pack('!HHHH',sp,dp,len(body)+8,0)+body,src,dst)

def tcp(body,src,dst,sp,dp,sequence):
    header=struct.pack('!HHIIBBHHH',sp,dp,sequence,0,0x50,0x18,65535,0,0)
    pseudo=socket.inet_aton(src)+socket.inet_aton(dst)+struct.pack('!BBH',0,6,len(header)+len(body))
    header=header[:16]+struct.pack('!H',checksum(pseudo+header+body))+header[18:]
    return ip(header+body,src,dst,6)

def rtp(payload,seq,stamp,pt,ssrc):
    return struct.pack('!BBHII',0x80,pt,seq&65535,stamp&0xffffffff,ssrc)+payload

def pcap(records):
    out=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,101))
    for us,data in sorted(records,key=lambda r:r[0]):
        seconds,part=divmod(us,1000000);out.extend(struct.pack('<IIII',seconds,part,len(data),len(data)));out.extend(data)
    return bytes(out)

def read_pcap(data):
    at=24;out=[]
    while at<len(data):
        sec,us,size,_=struct.unpack_from('<IIII',data,at);at+=16;out.append((sec*1000000+us,data[at:at+size]));at+=size
    return out

def ws(payload,masked=False,opcode=1,fin=True):
    head=bytes([(128 if fin else 0)|opcode,(128 if masked else 0)|(len(payload) if len(payload)<126 else 126)])
    if len(payload)>=126:head+=struct.pack('!H',len(payload))
    if masked:
        key=b'\x12\x34\x56\x78';return head+key+bytes(v^key[n%4] for n,v in enumerate(payload))
    return head+payload

def codec_frames(side,codec):
    suffix={'PCMU':'pcmu','PCMA':'pcma','G729':'g729','G729A':'g729','G722':'g722','OPUS':'opus','AMR':'amr','AMR-WB':'awb'}[codec]
    data=(INPUT/(side+'.'+suffix)).read_bytes()
    if codec=='OPUS':
        frames=[];at=0
        while at<len(data):
            length=struct.unpack_from('!H',data,at)[0];at+=2;frames.append(data[at:at+length]);at+=length
        return frames
    if codec in ('AMR','AMR-WB'):
        wide=codec=='AMR-WB';prefix=b'#!AMR-WB\n' if wide else b'#!AMR\n';assert data.startswith(prefix)
        at=len(prefix);frames=[]
        while at<len(data):
            toc=data[at];bits=(WB_BITS if wide else NB_BITS)[(toc>>3)&15];assert bits>=0
            size=(bits+7)//8;frames.append(bytes([0xf0,toc&0x7c])+data[at+1:at+1+size]);at+=1+size
        return frames
    size=20 if codec.startswith('G729') else 160
    assert len(data)%size==0
    return [data[n:n+size] for n in range(0,len(data),size)]

class Call:
    def __init__(self,number,slug,title,caller='PCMU',callee='PCMA',transport='UDP'):
        self.number=number;self.id='%02d-%s@demo.invalid'%(number,slug);self.title=title
        self.a='192.0.2.'+str(number);self.b='198.51.100.'+str(number)
        self.porta=30000+number*4;self.portb=self.porta+2
        self.caller='10%03d'%number;self.callee='20%03d'%number
        self.start=EPOCH+(number-1)*15000000;self.transport=transport;self.records=[];self.sequence=[1001,9001]
        self.codecs=[caller,callee];self.event=False
    def message(self,line,body=b'',cseq='1 INVITE',reverse=False,response=False,content='application/sdp',extra='',initial=False):
        fr='"%02d %s" <sip:%s@demo.invalid>;tag=caller%d'%(self.number,self.title,self.caller,self.number)
        to='<sip:%s@demo.invalid>'%self.callee+('' if initial else ';tag=callee'+str(self.number))
        if reverse and not response:fr,to=to,fr
        text=line+'\r\nVia: SIP/2.0/'+self.transport+' '+self.a+':5060;branch=z9hG4bK-demo-'+str(self.number)+'-'+cseq.replace(' ','-')+'\r\n'
        text+='From: '+fr+'\r\nTo: '+to+'\r\nCall-ID: '+self.id+'\r\nCSeq: '+cseq+'\r\nMax-Forwards: 70\r\nUser-Agent: ChaogeHuatan-Synthetic-Demo\r\n'+extra
        if body:text+='Content-Type: '+content+'\r\n'
        return (text+'Content-Length: '+str(len(body))+'\r\n\r\n').encode('utf-8')+body
    def wire(self,at,payload,reverse=False):
        src,dst=(self.b,self.a) if reverse else (self.a,self.b);when=self.start+at
        if self.transport=='UDP':self.records.append((when,udp(payload,src,dst,5060,5060)));return
        sp,dp=(5060,18000+self.number) if reverse else (18000+self.number,5060)
        if self.transport=='WS':
            midpoint=len(payload)//2;payload=ws(payload[:midpoint],not reverse,1,False)+ws(payload[midpoint:],not reverse,0,True)
        for offset in range(0,len(payload),211):
            part=payload[offset:offset+211];self.records.append((when+offset,tcp(part,src,dst,sp,dp,self.sequence[int(reverse)])));self.sequence[int(reverse)]+=len(part)
    def send(self,at,line,body=b'',cseq='1 INVITE',reverse=False,response=False,**kw):
        self.wire(at,self.message(line,body,cseq,reverse,response,**kw),reverse)
    def sdp(self,reverse=False,direction='sendrecv'):
        addr,port=(self.b,self.portb) if reverse else (self.a,self.porta)
        codecs=list(dict.fromkeys(self.codecs));pts=[str(CODECS[x][0]) for x in codecs]
        if self.event:pts+=['101','110']
        lines=['v=0','o=- %d 1 IN IP4 %s'%(self.number,addr),'s=%02d %s'%(self.number,self.title),'c=IN IP4 '+addr,'t=0 0','m=audio %d RTP/AVP %s'%(port,' '.join(pts))]
        for codec in codecs:
            pt,clock=CODECS[codec];lines.append('a=rtpmap:%d %s/%d%s'%(pt,'opus' if codec=='OPUS' else codec,clock,'/2' if codec=='OPUS' else ''))
            if codec in ('AMR','AMR-WB'):lines.append('a=fmtp:%d octet-align=1'%pt)
        if self.event:lines+=['a=rtpmap:101 telephone-event/8000','a=fmtp:101 0-16','a=rtpmap:110 rtpevent/8000','a=fmtp:110 0-16']
        lines+=['a=ptime:20','a='+direction]
        return ('\r\n'.join(lines)+'\r\n').encode('utf-8')
    def connect(self,extra=''):
        self.send(0,'INVITE sip:'+self.callee+'@demo.invalid SIP/2.0',self.sdp(),extra=extra,initial=True)
        self.send(50000,'SIP/2.0 100 Trying',reverse=True,response=True,initial=True)
        self.send(100000,'SIP/2.0 180 Ringing',reverse=True,response=True)
        self.send(200000,'SIP/2.0 200 OK',self.sdp(True),reverse=True,response=True)
        self.send(250000,'ACK sip:'+self.callee+'@demo.invalid SIP/2.0',cseq='1 ACK')
    def finish(self,at=11600000,reverse=False):
        target=self.caller if reverse else self.callee
        self.send(at,'BYE sip:'+target+'@demo.invalid SIP/2.0',cseq='900 BYE',reverse=reverse,extra='Reason: Q.850;cause=16;text="Normal call clearing"\r\n')
        self.send(at+50000,'SIP/2.0 200 OK',cseq='900 BYE',reverse=not reverse,response=True)
    def media(self,quality=False,keys=False,inband=False,oneway=False,hold=False,stalled=False):
        for direction,codec in enumerate(self.codecs[:1] if oneway else self.codecs):
            frames=codec_frames('callee' if direction else 'caller',codec);seq=65000 if keys else 1000
            for i,payload in enumerate(frames):
                if inband:
                    samples=[]
                    for j in range(160):
                        sample=i*160+j;key,phase=divmod(sample-1600,1920)
                        if 0<=key<16 and phase<960:
                            index=key if direction==0 else 15-key;freqs=[(697,770,852,941)[index//4],(1209,1336,1477,1633)[index%4]]
                            value=round(sum(4500*math.sin(2*math.pi*f*sample/8000) for f in freqs))
                        else:value=0
                        samples.append(value)
                    pcm=struct.pack('<160h',*samples);payload=audioop.lin2alaw(pcm,2) if codec=='PCMA' else audioop.lin2ulaw(pcm,2)
                if hold and 100<=i<200:continue
                stamp=i*CODECS[codec][1]//50
                if stalled and direction==1 and i>=120:stamp-=CODECS[codec][1]
                arrival=self.start+300000+i*20000+direction*1000
                if stalled and direction==1 and i>=120:arrival+=1000000
                if quality and direction==0:
                    if 70<=i<73:seq+=1;continue
                    if i>=120:arrival+=180000
                    if i==40:arrival+=50000
                packet=udp(rtp(payload,seq,stamp,CODECS[codec][0],0x100000+self.number*10+direction),self.b if direction else self.a,self.a if direction else self.b,self.portb if direction else self.porta,self.porta if direction else self.portb)
                self.records.append((arrival,packet));seq+=1
                if quality and direction==0 and i==90:self.records.append((arrival+2000,packet))
                if keys and i>=20 and (i-20)%15 in (0,1,2,3,4):
                    number=(i-20)//15;phase=(i-20)%15
                    if number<=16:
                        duration=min(480,(phase+1)*160);event=struct.pack('!BBH',number,0x88 if phase>=2 else 8,duration)
                        self.records.append((arrival+500,udp(rtp(event,seq,(20+number*15)*160,110 if direction else 101,0x100000+self.number*10+direction),self.b if direction else self.a,self.a if direction else self.b,self.portb if direction else self.porta,self.porta if direction else self.portb)));seq+=1

def calls():
    specs=[('g711','G.711 双向语音','PCMU','PCMA'),('g729','G.729 与 G.729A','G729','G729A'),('opus','Opus 双向语音','OPUS','OPUS'),('g722','G.722 宽带语音','G722','G722'),('amr-nb','AMR-NB 双向语音','AMR','AMR'),('amr-wb','AMR-WB 双向语音','AMR-WB','AMR-WB'),('rtp-event','2833 全按键与动态 PT','PCMU','PCMA'),('sip-info','INFO 两种格式全按键','PCMU','PCMA'),('inband','In-band 全按键','PCMU','PCMA'),('quality','丢包 延迟 乱序 重复','PCMU','PCMA'),('hold','保持与恢复 被叫挂断','PCMU','PCMA'),('tcp','TCP 分段信令','PCMU','PCMA'),('websocket','WebSocket 分帧信令','OPUS','OPUS'),('busy','被叫忙 486','PCMU','PCMA'),('cancel','主叫取消 CANCEL','PCMU','PCMA'),('timeout','信令重传与 408 超时','PCMU','PCMA'),('partial','单向媒体 结束未捕获','PCMU','PCMA'),('transfer-from','转接原通话 REFER','PCMU','PCMA'),('transfer-to','转接后通话 Replaces','PCMU','PCMA'),('timestamp','RTP 时钟停顿与双向对齐','PCMU','PCMA'),('dtx','静音抑制 正常媒体间隔','PCMU','PCMA'),('tls-rsa','TLS 1.2 RSA 解密','PCMU','PCMA'),('wss','TLS 1.3 WSS 解密','OPUS','OPUS')]
    return [Call(n,slug,title,a,b,'TCP' if n==12 else 'WS' if n==13 else 'UDP') for n,(slug,title,a,b) in enumerate(specs,1)]

def main():
    metadata=json.loads((INPUT/'audio.json').read_text(encoding='utf-8'))
    for name,digest in metadata['files_sha256'].items():assert hashlib.sha256((INPUT/name).read_bytes()).hexdigest()==digest,name
    values=calls();records=[]
    for call in values:
        n=call.number
        if n>=22:
            records+=read_pcap((INPUT/('tls-rsa.pcap' if n==22 else 'wss.pcap')).read_bytes());call.media()
            # Encrypted BYE/200 are already included in the saved TLS connection.
            records.extend((t,p) for t,p in call.records if p[9]==17 and struct.unpack_from('!H',p,20)[0]!=5060)
            continue
        if n in (14,15,16):
            invite=call.message('INVITE sip:'+call.callee+'@demo.invalid SIP/2.0',call.sdp(),initial=True);call.wire(0,invite)
            if n==16:call.wire(500000,invite);call.wire(1500000,invite)
            else:call.send(100000,'SIP/2.0 180 Ringing',reverse=True,response=True)
            if n==15:
                call.send(2000000,'CANCEL sip:'+call.callee+'@demo.invalid SIP/2.0',cseq='1 CANCEL');call.send(2050000,'SIP/2.0 200 OK',cseq='1 CANCEL',reverse=True,response=True);call.send(2100000,'SIP/2.0 487 Request Terminated',reverse=True,response=True)
            else:call.send(2500000,'SIP/2.0 '+('486 Busy Here' if n==14 else '408 Request Timeout'),reverse=True,response=True)
            call.send(2600000,'ACK sip:'+call.callee+'@demo.invalid SIP/2.0',cseq='1 ACK');records+=call.records;continue
        call.event=n==7
        call.connect(extra=('Replaces: '+values[17].id+';to-tag=callee18;from-tag=caller18\r\n') if n==19 else '')
        call.media(quality=n==10,keys=n==7,inband=n==9,oneway=n==17,hold=n in (11,21),stalled=n==20)
        if n==8:
            for reverse in (False,True):
                for index,key in enumerate(KEYS):
                    at=600000+index*230000+(4500000 if reverse else 0);cseq=str((100 if reverse else 10)+index)+' INFO'
                    body=(key if reverse else 'Signal='+str(index)+'\r\nDuration=120\r\n').encode()
                    call.send(at,'INFO sip:'+(''+call.caller if reverse else call.callee)+'@demo.invalid SIP/2.0',body,cseq,reverse,content='application/dtmf' if reverse else 'application/dtmf-relay')
                    if not reverse and index==5:call.send(at+30000,'INFO sip:'+call.callee+'@demo.invalid SIP/2.0',body,cseq,content='application/dtmf-relay')
                    call.send(at+70000,'SIP/2.0 200 OK',cseq=cseq,reverse=not reverse,response=True)
        if n==11:
            for at,cseq,mode in [(2100000,2,'sendonly'),(4300000,3,'sendrecv')]:
                call.send(at,'INVITE sip:'+call.callee+'@demo.invalid SIP/2.0',call.sdp(direction=mode),str(cseq)+' INVITE')
                call.send(at+50000,'SIP/2.0 200 OK',call.sdp(True,'recvonly' if mode=='sendonly' else 'sendrecv'),str(cseq)+' INVITE',True,True)
                call.send(at+100000,'ACK sip:'+call.callee+'@demo.invalid SIP/2.0',cseq=str(cseq)+' ACK')
        if n==18:
            target=values[18]
            call.send(8000000,'REFER sip:'+call.callee+'@demo.invalid SIP/2.0',cseq='20 REFER',extra='Refer-To: <sip:'+target.callee+'@demo.invalid?Replaces='+target.id+'%3Bto-tag%3Dcallee19%3Bfrom-tag%3Dcaller19>\r\n')
            call.send(8050000,'SIP/2.0 202 Accepted',cseq='20 REFER',reverse=True,response=True)
            call.send(8100000,'NOTIFY sip:'+call.caller+'@demo.invalid SIP/2.0',b'SIP/2.0 200 OK\r\n',cseq='21 NOTIFY',reverse=True,content='message/sipfrag',extra='Event: refer\r\nSubscription-State: terminated\r\n')
            call.send(8150000,'SIP/2.0 200 OK',cseq='21 NOTIFY',response=True)
        if n!=17:call.finish(at=12800000 if n==20 else 11600000,reverse=n in (2,4,6,11,19))
        records+=call.records
    data=pcap(records);FIXTURES.mkdir(parents=True,exist_ok=True);(FIXTURES/'demo-showcase.pcap').write_bytes(data)
    assets=ROOT/('app/src/main/assets' if (ROOT/'app').exists() else 'src/main/resources');assets.mkdir(parents=True,exist_ok=True)
    (assets/'demo-analysis.pcap').write_bytes(data)
    for name in ('demo-rsa.key','demo-tls.keys'):(assets/name).write_bytes((INPUT/name).read_bytes())
    guide='超哥话探 · 多通话演示\n\n同一抓包包含 23 通合成通话，未使用真实号码或通话。\n默认展示第 01 通；切换通话查看场景，点「全部」查看完整抓包。\n号码规律：主叫 10001～10023，被叫 20001～20023。可按号码、IP、时间或 Call-ID 中的英文场景名搜索。\n\n'
    guide+='\n'.join('%02d  %s  ·  %s → %s'%(c.number,c.title,c.caller,c.callee) for c in values)
    guide+='\n\n07：两个方向分别使用 telephone-event 与 rtpevent，含动态 PT、序号回绕、结束包重复；各含 0～9、*、#、A～D 和 Flash。\n08：双向 INFO，分别展示 application/dtmf-relay 和 application/dtmf，各含完整 16 键；包含重传去重。\n09：双向 G.711 音内按键，各含完整 16 键。\n01～06：实际合成中文对话，可试听、查看双向波形、缩放并导出一个多声道 WAV。G.729A 使用兼容的 G.729 比特流。AMR 使用 octet-align=1，播放取决于本机解码器。\n22、23：先显示加密信令提示；在本演示的解密菜单分别加载演示 RSA 私钥、TLS key log 后重新分析，显示对应通话。演示密钥仅匹配这些合成会话。\n\n可继续体验通话体检、按键摘要、REFER/Replaces 关联、按通话导出抓包、HTML 报告以及号码/IP 分别遮蔽。导出的 WAV 可用于「导入录音转文字」；RTP 转写和录音转写均需先导入离线模型，不会自动下载。\n丢包、延迟和单向媒体仅代表抓包中可见的证据，不等同于实际听感。\n'
    (assets/'demo-guide.txt').write_text(guide,encoding='utf-8')
    (FIXTURES/'demo-showcase.json').write_text(json.dumps({'synthetic_only':True,'sha256':hashlib.sha256(data).hexdigest(),'packets':len(records),'calls':[{'number':c.number,'id':c.id,'title':c.title,'caller':c.caller,'callee':c.callee,'codecs':c.codecs} for c in values]},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Generated showcase: 23 calls, %d packets, %.2f MiB'%(len(records),len(data)/1048576),flush=True)

if __name__=='__main__':main()
