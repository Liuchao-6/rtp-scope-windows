package com.liuchao.rtpscope.desktop;

import javax.sound.sampled.*;
import java.io.*;

/** PCM WAV playback using Windows audio devices through Java Sound. Loaded off the UI thread. */
public final class WavPlayer implements AutoCloseable {
    private Clip clip;
    private float volume=0.8f;
    public synchronized void load(File file) throws IOException,UnsupportedAudioFileException,LineUnavailableException {
        close();Clip created=AudioSystem.getClip();
        try(AudioInputStream input=AudioSystem.getAudioInputStream(file)){created.open(input);}catch(IOException|UnsupportedAudioFileException|LineUnavailableException|RuntimeException e){created.close();throw e;}
        clip=created;setVolume(volume);
    }
    public synchronized boolean ready(){return clip!=null;}
    public synchronized boolean playing(){return clip!=null&&clip.isRunning();}
    public synchronized long duration(){return clip==null?0:clip.getMicrosecondLength()/1000;}
    public synchronized long position(){return clip==null?0:clip.getMicrosecondPosition()/1000;}
    public synchronized void play(){if(clip!=null){if(clip.getFramePosition()>=clip.getFrameLength())clip.setFramePosition(0);clip.start();}}
    public synchronized void pause(){if(clip!=null)clip.stop();}
    public synchronized void seek(long ms){if(clip!=null)clip.setMicrosecondPosition(Math.max(0,Math.min(clip.getMicrosecondLength(),ms*1000)));}
    public synchronized void setVolume(float value){volume=Math.max(0,Math.min(1,value));if(clip!=null&&clip.isControlSupported(FloatControl.Type.MASTER_GAIN)){FloatControl c=(FloatControl)clip.getControl(FloatControl.Type.MASTER_GAIN);c.setValue(Math.max(c.getMinimum(),Math.min(c.getMaximum(),volume<=0?c.getMinimum():(float)(20*Math.log10(volume)))));}}
    public synchronized void close(){if(clip!=null){clip.stop();clip.close();clip=null;}}
}
