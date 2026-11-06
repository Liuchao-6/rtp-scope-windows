"""Package a local verified ASR model separately from the application."""
from pathlib import Path
import argparse, hashlib, json, zipfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('model_directory', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    parser.add_argument('--type', choices=['whisper','sensevoice'], default='whisper')
    args = parser.parse_args()
    sensevoice=args.type=='sensevoice'
    metadata = json.loads((ROOT / ('third_party/sensevoice-int8.json' if sensevoice else 'third_party/whisper-tiny.json')).read_text(encoding='utf-8'))
    args.output.mkdir(parents=True, exist_ok=True)
    label='SenseVoice-Small-int8' if sensevoice else 'Whisper-tiny-int8'
    target = args.output / ('Huatan-SenseVoice-int8.zip' if sensevoice else 'Huatan-Whisper-tiny-int8.zip')
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, digest in metadata['files'].items():
            model = args.model_directory / name
            assert hashlib.sha256(model.read_bytes()).hexdigest() == digest, 'Model SHA-256 mismatch'
            archive.write(model, label+'/' + name)
        if sensevoice:
            archive.writestr(label+'/model.properties','type=sensevoice\nname=SenseVoice Small int8\n')
            archive.writestr(label+'/模型来源.txt','FunAudioLLM SenseVoice Small\nConverted for sherpa-onnx by csukuangfj / k2-fsa\n'+metadata['source']+'\nrevision='+metadata['revision']+'\n')
        for name in (['sensevoice-MODEL-LICENSE.txt','sensevoice-upstream-LICENSE.txt','sherpa-onnx-LICENSE.txt'] if sensevoice else ['whisper-MIT.txt', 'sherpa-onnx-LICENSE.txt']):
            archive.write(ROOT / 'src/main/resources/licenses' / name, label+'/' + name)
        archive.write(ROOT / 'packaging/模型使用说明.txt', '模型使用说明.txt')
    with zipfile.ZipFile(target) as archive:
        assert archive.testzip() is None
        assert not any(name.lower().endswith('.md') for name in archive.namelist())
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_name(target.name + '.sha256').write_text(digest + '  ' + target.name + '\n', encoding='utf-8')
    print(str(target) + ' bytes=' + str(target.stat().st_size))

if __name__ == '__main__':
    main()
