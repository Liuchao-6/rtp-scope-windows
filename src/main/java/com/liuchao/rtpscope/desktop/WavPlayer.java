package com.liuchao.rtpscope.desktop;

import javax.sound.sampled.*;
import java.io.*;

/** PCM WAV playback using Windows audio devices through Java Sound. Loaded off the UI thread. */
public final class WavPlayer implements AutoCloseable {
    private Clip clip;
    private float volume=0.8f;
    private float speed=1;
    private File original,adjusted;
    private long loopA=-1,loopB=-1;
    public void load(File file) throws IOException,UnsupportedAudioFileException,LineUnavailableException {
        float selectedSpeed; synchronized(this){selectedSpeed=speed;}File playable=file,converted=null;
        if(selectedSpeed!=1){converted=File.createTempFile("huatan-speed-",".wav");try{NativeMedia.run(java.util.Arrays.asList("-i",file.getAbsolutePath(),"-filter:a","atempo="+selectedSpeed,"-c:a","pcm_s16le",converted.getAbsolutePath()));playable=converted;}catch(IOException e){converted.delete();throw e;}}
        Clip created=AudioSystem.getClip();
        try(AudioInputStream input=AudioSystem.getAudioInputStream(playable)){created.open(input);}catch(IOException|UnsupportedAudioFileException|LineUnavailableException|RuntimeException e){created.close();if(converted!=null)converted.delete();throw e;}
        synchronized(this){close();original=file;adjusted=converted;clip=created;setVolume(volume);}
    }
    public synchronized boolean ready(){return clip!=null;}
    public synchronized boolean playing(){return clip!=null&&clip.isRunning();}
    public synchronized long duration(){return clip==null?0:(long)(clip.getMicrosecondLength()/1000*speed);}
    public synchronized long position(){return clip==null?0:(long)(clip.getMicrosecondPosition()/1000*speed);}
    public synchronized void play(){if(clip!=null){if(loopA>=0&&loopB>loopA&&loopA<duration()){long end=Math.min(loopB,duration());if(position()<loopA||position()>=end)seek(loopA);int a=(int)(loopA/1000.0/speed*clip.getFormat().getFrameRate()),b=Math.min(clip.getFrameLength()-1,(int)(end/1000.0/speed*clip.getFormat().getFrameRate()));clip.setLoopPoints(a,Math.max(a,b));clip.loop(Clip.LOOP_CONTINUOUSLY);}else{if(clip.getFramePosition()>=clip.getFrameLength())clip.setFramePosition(0);clip.start();}}}
    public synchronized void pause(){if(clip!=null)clip.stop();}
    public synchronized void seek(long ms){if(clip!=null)clip.setMicrosecondPosition(Math.max(0,Math.min(clip.getMicrosecondLength(),(long)(ms*1000/speed))));}
    public void setSpeed(float value)throws IOException,UnsupportedAudioFileException,LineUnavailableException{if(value<.5f||value>2)throw new IOException("倍速范围 0.5～2.0");long position;boolean running;File file;synchronized(this){position=position();running=playing();file=original;speed=value;}if(file!=null){load(file);seek(position);if(running)play();}}
    public synchronized void setLoop(long a,long b){loopA=a;loopB=b;if(clip!=null){boolean running=playing();clip.stop();clip.setLoopPoints(0,-1);if(running)play();}}
    public synchronized void setVolume(float value){volume=Math.max(0,Math.min(1,value));if(clip!=null&&clip.isControlSupported(FloatControl.Type.MASTER_GAIN)){FloatControl c=(FloatControl)clip.getControl(FloatControl.Type.MASTER_GAIN);c.setValue(Math.max(c.getMinimum(),Math.min(c.getMaximum(),volume<=0?c.getMinimum():(float)(20*Math.log10(volume)))));}}
    public synchronized void close(){if(clip!=null){clip.stop();clip.close();clip=null;}if(adjusted!=null)adjusted.delete();adjusted=null;original=null;}
}
