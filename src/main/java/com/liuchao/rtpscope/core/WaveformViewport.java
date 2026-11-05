package com.liuchao.rtpscope.core;

/** A shared, bounded time window for zoom, pan, ticks, markers and hit testing. */
public final class WaveformViewport {
    private double duration=1,start,zoom=1;
    public void reset(double ms){duration=Math.max(1,ms);start=0;zoom=1;}
    public double durationMs(){return duration;}
    public double startMs(){return start;}
    public double spanMs(){return duration/zoom;}
    public double endMs(){return Math.min(duration,start+spanMs());}
    public double zoom(){return zoom;}
    public void fit(){zoom=1;start=0;}
    public void zoomAt(double factor,double anchor){double ratio=Math.max(0,Math.min(1,anchor)),time=start+spanMs()*ratio;zoom=Math.max(1,Math.min(64,zoom*factor));setStartMs(time-spanMs()*ratio);}
    public void setStartMs(double ms){start=Math.max(0,Math.min(duration-spanMs(),ms));}
    public void pan(double ms){setStartMs(start+ms);}
    public double timeAt(double fraction){return Math.max(0,Math.min(duration,start+Math.max(0,Math.min(1,fraction))*spanMs()));}
    public double fractionAt(double ms){return (ms-start)/spanMs();}
    public boolean contains(double ms){return ms>=start&&ms<=endMs();}
    public void reveal(double ms){if(!contains(ms))setStartMs(ms-spanMs()/2);}
}
