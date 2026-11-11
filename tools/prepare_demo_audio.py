"""Optional Windows-only preparation of public synthetic speech and codec inputs.

Normal builds use the saved inputs; they need neither speech synthesis nor encoders.
Requires Windows SAPI, a local FFmpeg with AMR/Opus encoders and the Java toolchain.
"""
from pathlib import Path
import argparse, base64, hashlib, json, struct, subprocess, tempfile, wave

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'tests/fixtures/demo-audio'

def run(args):
    subprocess.run([str(x) for x in args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)

def ogg_packets(data):
    pending=bytearray();packets=[];at=0
    while at<len(data):
        assert data[at:at+4]==b'OggS'
        count=data[at+26];lengths=data[at+27:at+27+count];pos=at+27+count
        for length in lengths:
            pending.extend(data[pos:pos+length]);pos+=length
            if length<255:packets.append(bytes(pending));pending.clear()
        at=pos
    assert not pending
    return packets[2:]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--ffmpeg',type=Path,required=True);args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    java=ROOT/'.tools/runtime/bin/java.exe' if (ROOT/'.tools/runtime/bin/java.exe').exists() else Path(r'C:\Program Files\Java\jre1.8.0_511\bin/java.exe')
    g729=ROOT/('src/main/java' if (ROOT/'src').exists() else 'app/src/main/java')/'org/jitsi/impl/neomedia/codec/audio/g729'
    with tempfile.TemporaryDirectory() as temporary:
        temp=Path(temporary);speech=[]
        for side,voice,words in [('caller','Microsoft Kangkang','你好，这里是超哥话探，通话声音是否清楚？'),('callee','Microsoft Huihui Desktop','声音清楚，现在测试双向语音和通话分析。')]:
            target=temp/(side+'.wav')
            script="Add-Type -AssemblyName System.Speech; $s=New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.SelectVoice('"+voice+"'); $s.Rate=1; $f=New-Object System.Speech.AudioFormat.SpeechAudioFormatInfo(16000,[System.Speech.AudioFormat.AudioBitsPerSample]::Sixteen,[System.Speech.AudioFormat.AudioChannel]::Mono); $s.SetOutputToWaveFile('"+str(target).replace("'","''")+"',$f); $s.Speak('"+words+"'); $s.Dispose()"
            run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()])
            with wave.open(str(target),'rb') as w:
                assert w.getframerate()==16000 and w.getnchannels()==1;speech.append(w.readframes(w.getnframes()))
        gap=b'\0'*(16000*2//3);tracks=[gap+speech[0]+gap+b'\0'*len(speech[1])+gap,gap+b'\0'*len(speech[0])+gap+speech[1]+gap]
        size=((max(map(len,tracks))+639)//640)*640
        classes=temp/'classes';classes.mkdir()
        run([java,'-jar',ROOT/'.tools/ecj.jar','-1.8','-encoding','UTF-8','-nowarn','-d',classes,*sorted(g729.glob('*.java')),ROOT/'tools/DemoAudioFixture.java'])
        encoders={'pcmu':('pcm_mulaw',8000,'mulaw',[]),'pcma':('pcm_alaw',8000,'alaw',[]),'g722':('g722',16000,'g722',[]),'opus':('libopus',48000,'opus',['-b:a','24000','-vbr','off','-frame_duration','20']),'amr':('libopencore_amrnb',8000,'amr',['-b:a','12.2k']),'awb':('libvo_amrwbenc',16000,'amr',['-b:a','12.65k'])}
        for side,pcm in zip(['caller','callee'],tracks):
            source=OUT/(side+'.wav')
            with wave.open(str(source),'wb') as w:w.setnchannels(1);w.setsampwidth(2);w.setframerate(16000);w.writeframes(pcm.ljust(size,b'\0'))
            for suffix,(codec,rate,fmt,extra) in encoders.items():
                target=OUT/(side+'.'+suffix)
                run([args.ffmpeg,'-hide_banner','-loglevel','error','-y','-i',source,'-ac','1','-ar',rate,'-c:a',codec,*extra,'-f',fmt,target])
                if suffix=='opus':
                    packets=ogg_packets(target.read_bytes())[:size//640]
                    assert len(packets)==size//640
                    target.write_bytes(b''.join(struct.pack('!H',len(p))+p for p in packets))
            raw=temp/(side+'.pcm');run([args.ffmpeg,'-hide_banner','-loglevel','error','-y','-i',source,'-ar','8000','-f','s16le',raw])
            run([java,'-cp',classes,'org.jitsi.impl.neomedia.codec.audio.g729.DemoAudioFixture',raw,OUT/(side+'.g729')])
    files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(OUT.iterdir()) if p.is_file() and p.suffix in ('.wav','.pcmu','.pcma','.g722','.opus','.amr','.awb','.g729')}
    (OUT/'audio.json').write_text(json.dumps({'synthetic_only':True,'source':'Local Windows SAPI speech synthesis; no recorded calls','caller_text':'你好，这里是超哥话探，通话声音是否清楚？','callee_text':'声音清楚，现在测试双向语音和通话分析。','frames':size//640,'files_sha256':files},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Prepared synthetic speech: '+str(size//640)+' frames per direction')

if __name__=='__main__':main()
