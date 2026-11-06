package com.liuchao.rtpscope.core;
import com.k2fsa.sherpa.onnx.*;
import java.io.*;
import java.util.*;

/** Local inference. Short source-time windows bound memory and cancellation latency. */
public final class SpeechTranscriber implements Closeable {
    public interface Progress {void update(String phase,int percent);}
    private final OfflineRecognizer recognizer;
    private final boolean senseVoice;private final String language;
    public SpeechTranscriber(SpeechModels.Model model,String language){
        this.language=language;senseVoice=model.type==SpeechModels.Type.SENSE_VOICE;
        OfflineModelConfig.Builder config=OfflineModelConfig.builder().setTokens(model.tokens.getAbsolutePath()).setNumThreads(Math.max(1,Math.min(4,Runtime.getRuntime().availableProcessors()/2))).setDebug(false);
        if(senseVoice)config.setSenseVoice(OfflineSenseVoiceModelConfig.builder().setModel(model.network.getAbsolutePath()).setLanguage(language).setInverseTextNormalization(true).build()).setModelType("sense_voice");
        else config.setWhisper(OfflineWhisperModelConfig.builder().setEncoder(model.encoder.getAbsolutePath()).setDecoder(model.decoder.getAbsolutePath()).setLanguage(language.equals("auto")?"":language).setTask("transcribe").setEnableTokenTimestamps(true).setEnableSegmentTimestamps(true).build());
        recognizer=new OfflineRecognizer(OfflineRecognizerConfig.builder().setOfflineModelConfig(config.build()).build());
    }
    public Transcript transcribe(File wav,boolean separate,Progress progress)throws IOException{
        Transcript result=new Transcript();try(PcmFile pcm=new PcmFile(wav)){
            int tracks=separate?pcm.channels:1;long duration=(long)Math.ceil(pcm.durationMs());
            for(int channel=0;channel<tracks;channel++){
            progress.update("检测语音片段 · "+(channel+1)+" / "+tracks,(int)(channel*100/tracks));
            List<VoiceSegments.Window> windows=VoiceSegments.find(pcm,separate?channel:-1);
            for(VoiceSegments.Window window:windows){long at=window.startMs;
                if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("转写已取消");
                float[] audio=pcm.read(at,(int)(window.endMs-at),separate?channel:-1,16000);double energy=0;for(float v:audio)energy+=v*v;
                progress.update("语音识别 · "+(channel+1)+" / "+tracks,(int)((channel*duration+at)*100/Math.max(1,tracks*duration)));
                if(audio.length<1600||energy/audio.length<0.000001)continue;
                OfflineStream stream=recognizer.createStream();
                try{stream.acceptWaveform(audio,16000);recognizer.decode(stream);if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("转写已取消");OfflineRecognizerResult recognized=recognizer.getResult(stream);String text=recognized.getText().trim();
                    String detected=language.equals("auto")?recognized.getLang():language;if(detected==null)detected="";detected=detected.replace("<|","").replace("|>","");
                    if(senseVoice)text=text.replaceAll("<\\|[^>]*\\|>","").trim();int first=result.segments.size();
                    if(!text.isEmpty()){
                        String[] tokens=recognized.getTokens();float[] stamps=recognized.getTimestamps();float[] durations=recognized.getDurations();String label=separate?PcmFile.channelName(pcm.channels,channel):pcm.channels==1?"单声道":"混合";
                        if(!senseVoice&&tokens!=null&&stamps!=null&&tokens.length==stamps.length&&tokens.length>0){StringBuilder sentence=new StringBuilder();long start=at,end=at;for(int i=0;i<tokens.length;i++){String word=tokens[i];if(word.matches("<\\|.*\\|>"))continue;if(sentence.length()==0)start=at+Math.max(0,Math.round(stamps[i]*1000));sentence.append(word.replace('▁',' '));end=Math.min(duration,at+Math.round((stamps[i]+(durations!=null&&durations.length>i?durations[i]:.3f))*1000));if(word.matches("(?s).*[。！？.!?]$")){result.segments.add(new Transcript.Segment(start,Math.max(start+1,end),label,sentence.toString().trim()));sentence.setLength(0);}}if(sentence.length()>0)result.segments.add(new Transcript.Segment(start,Math.max(start+1,end),label,sentence.toString().trim()));}
                        else result.segments.add(new Transcript.Segment(at,Math.min(duration,at+audio.length/16),label,text));
                    }
                    for(int i=first;i<result.segments.size();i++)result.segments.get(i).language=detected;
                }finally{stream.release();}
            }}
        }result.simplifyChinese(language.equals("zh"));result.sort();progress.update("文字整理完成",100);return result;
    }
    public void close(){recognizer.release();}
}
