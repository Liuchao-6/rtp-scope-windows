"""Build/test the standalone Windows app and package a verified private runtime."""
from pathlib import Path
import hashlib,json,os,shutil,struct,subprocess,sys,zipfile

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.5.0'
TOOLS=ROOT/'.tools'; BUILD=ROOT/'build'; DIST=ROOT/'dist'
RUNTIME=TOOLS/'runtime'
JAVA=RUNTIME/'bin/java.exe'
CSC=Path(os.environ.get('WINDIR',r'C:\Windows'))/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'

def run(args):
    normalized=[str(a.relative_to(ROOT)) if isinstance(a,Path) and a.is_relative_to(ROOT) else str(a) for a in args]
    print('Running '+normalized[0]+' '+(normalized[1] if len(normalized)>1 else ''),flush=True)
    subprocess.run(normalized,cwd=ROOT,check=True)

def runtime():
    archive=TOOLS/'temurin-jre8-windows-x64.zip'; info=json.loads((ROOT/'third_party/runtime.json').read_text(encoding='utf-8'))
    if not archive.is_file():raise SystemExit('Download '+info['url']+' to '+str(archive))
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==info['sha256'],'Runtime SHA-256 mismatch'
    if not JAVA.is_file():
        with zipfile.ZipFile(archive) as z:
            assert z.testzip() is None
            for entry in z.infolist():
                parts=Path(entry.filename).parts
                if entry.is_dir() or len(parts)<2:continue
                target=RUNTIME.joinpath(*parts[1:]);assert target.resolve().is_relative_to(RUNTIME.resolve())
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(entry))
    print('Verified Eclipse Temurin runtime',flush=True)

def icon(path):
    size=64; pixels=bytearray()
    heights=[14,26,42,30,18]
    for y in reversed(range(size)):
        for x in range(size):
            mint=any(11+i*9<=x<16+i*9 and 32-h//2<=y<32+h//2 for i,h in enumerate(heights))
            r,g,b=(255,255,255) if mint else (0,103,192);pixels.extend((b,g,r,255))
    mask=bytes(((size+31)//32)*4*size);dib=struct.pack('<IiiHHIIiiII',40,size,size*2,1,32,0,len(pixels)+len(mask),0,0,0,0)+pixels+mask
    path.write_bytes(struct.pack('<HHH',0,1,1)+struct.pack('<BBBBHHII',size,size,0,0,1,32,len(dib),22)+dib)

def checksum(path):path.with_name(path.name+'.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n',encoding='utf-8')

def main():
    BUILD.mkdir(exist_ok=True);DIST.mkdir(exist_ok=True);runtime()
    compiler=TOOLS/'ecj.jar'
    if not compiler.is_file():raise SystemExit('Place Eclipse ECJ 3.21.0 in .tools/ecj.jar (see README)')
    toolchain=json.loads((ROOT/'third_party/toolchain.json').read_text(encoding='utf-8'))
    assert hashlib.sha256(compiler.read_bytes()).hexdigest()==toolchain['ecj']['sha256'],'Compiler SHA-256 mismatch'
    laf=ROOT/'third_party/flatlaf-3.6.2.jar';laf_info=json.loads((ROOT/'third_party/flatlaf.json').read_text(encoding='utf-8'))
    assert hashlib.sha256(laf.read_bytes()).hexdigest()==laf_info['sha256'],'FlatLaf SHA-256 mismatch'
    classes=BUILD/'classes';classes.mkdir(exist_ok=True)
    sources=sorted((ROOT/'src/main/java').rglob('*.java'))
    run([JAVA,'-jar',compiler,'-1.8','-encoding','UTF-8','-nowarn','-classpath',laf,'-d',classes]+sources)
    for p in (ROOT/'src/main/resources').rglob('*'):
        if p.is_file():target=classes/p.relative_to(ROOT/'src/main/resources');target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
    if '--skip-tests' not in sys.argv:
        tests=BUILD/'test-classes';tests.mkdir(exist_ok=True)
        run([JAVA,'-jar',compiler,'-1.8','-encoding','UTF-8','-nowarn','-classpath',os.pathsep.join([str(classes),str(laf)]),'-d',tests]+sorted((ROOT/'tests').glob('*.java')))
        cp=os.pathsep.join([str(classes.relative_to(ROOT)),str(tests.relative_to(ROOT)),str(laf.relative_to(ROOT))])
        run([JAVA,'-ea','-Djava.awt.headless=true','-cp',cp,'CoreTest',ROOT/'tests/fixtures',BUILD])
        run([JAVA,'-ea','-Djava.awt.headless=true','-cp',cp,'com.liuchao.rtpscope.desktop.DesktopTest',ROOT/'tests/fixtures',BUILD])
        run([JAVA,'-Djava.awt.headless=true','-cp',cp,'com.liuchao.rtpscope.desktop.AudioProbe',BUILD/'demo-desktop.wav',BUILD/'audio-probe.txt'])
        run([JAVA,'-Xmx160m','-cp',cp,'LargeCaptureTest',ROOT/'tests/fixtures',BUILD])
    if '--test-only' in sys.argv:return
    staging=BUILD/'release';staging.mkdir(exist_ok=True)
    product=staging/('ChaogeHuatan-'+VERSION+'-win-x64')
    # Recreate the private staging folder; an extracted app in dist may still be running.
    assert BUILD.resolve().parent==ROOT.resolve() and staging.resolve().parent==BUILD.resolve() and product.resolve().parent==staging.resolve()
    assert not product.is_symlink(),'Refusing to replace a linked release directory'
    if product.exists():shutil.rmtree(product)
    (product/'app').mkdir(parents=True,exist_ok=True)
    jar=product/'app/chaoge-huatan.jar'
    with zipfile.ZipFile(jar,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\r\nMain-Class: com.liuchao.rtpscope.desktop.DesktopApp\r\nClass-Path: lib/flatlaf-3.6.2.jar\r\n\r\n')
        for p in sorted(classes.rglob('*')):
            if p.is_file():z.write(p,p.relative_to(classes).as_posix())
    icon(BUILD/'app.ico')
    (product/'app/lib').mkdir(exist_ok=True);shutil.copy2(laf,product/'app/lib'/laf.name)
    run([CSC,'/nologo','/target:winexe','/platform:x64','/optimize+','/utf8output','/codepage:65001','/reference:System.Windows.Forms.dll','/win32manifest:launcher/app.manifest','/win32icon:build/app.ico','/out:'+str((product/'ChaogeHuatan.exe').relative_to(ROOT)),ROOT/'launcher/Launcher.cs'])
    shutil.copytree(RUNTIME,product/'runtime',dirs_exist_ok=True)
    for name in ['使用说明.txt','第三方许可.txt']:shutil.copy2(ROOT/'packaging'/name,product/name)
    # Exercise the real EXE -> bundled javaw -> JAR path without opening an audio device.
    result=BUILD/'启动验证 结果.txt'
    if result.exists():result.unlink()
    run([product/'ChaogeHuatan.exe','--diagnostics',str(result)])
    assert result.is_file(),'Native launcher diagnostic missing'
    diagnostic=result.read_text(encoding='utf-8')
    assert all(value in diagnostic for value in ['flow=8','wave_tracks=2','ui=FlatLaf']),'Native launcher diagnostic failed'
    archive=DIST/(product.name+'.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for p in sorted(product.rglob('*')):
            if p.is_file():z.write(p,product.name+'/'+p.relative_to(product).as_posix())
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        assert not any(name.lower().endswith('.md') for name in z.namelist())
    checksum(archive)
    source=DIST/('ChaogeHuatan-windows-source-'+VERSION+'.zip')
    with zipfile.ZipFile(source,'w',zipfile.ZIP_DEFLATED) as z:
        for folder in ['src','launcher','tools','tests','third_party','packaging']:
            for p in sorted((ROOT/folder).rglob('*')):
                if p.is_file() and '__pycache__' not in p.parts:z.write(p,'rtp-scope-windows/'+p.relative_to(ROOT).as_posix())
        z.write(ROOT/'.gitignore','rtp-scope-windows/.gitignore')
        z.write(ROOT/'packaging/source-readme.txt','rtp-scope-windows/README.txt')
        z.write(ROOT/'THIRD_PARTY_NOTICES.md','rtp-scope-windows/THIRD_PARTY_NOTICES.txt')
    with zipfile.ZipFile(source) as z:
        assert z.testzip() is None
        assert not any(name.lower().endswith('.md') for name in z.namelist())
    checksum(source);print('Portable ZIP: '+str(archive),flush=True)

if __name__=='__main__':main()
