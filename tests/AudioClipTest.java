import com.liuchao.rtpscope.core.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** Exact PCM excerpts, multi-channel timeline alignment and non-destructive failure paths. */
public final class AudioClipTest {
    private static int checks;
    private static void check(boolean ok,String text){checks++;if(!ok)throw new AssertionError(text);}
    private static byte[] data(File file)throws IOException{try(PcmFile pcm=new PcmFile(file);RandomAccessFile in=new RandomAccessFile(file,"r")){byte[] bytes=new byte[(int)(pcm.frames*pcm.channels*(pcm.bits/8))];in.seek(pcm.offset);in.readFully(bytes);return bytes;}}
    private static void rejected(File source,File target,double a,double b)throws Exception{byte[] previous=Files.readAllBytes(target.toPath());try{AudioClip.save(source,target,a,b);throw new AssertionError("invalid clip accepted");}catch(IOException expected){check(Arrays.equals(previous,Files.readAllBytes(target.toPath())),"invalid clip preserves existing destination");}}
    public static int run(File output)throws Exception{
        File dir=new File(output,"audio-clip-core");dir.mkdirs();Random random=new Random(78191);
        for(int channels:new int[]{1,2,3,4})for(int bits:new int[]{8,16,24,32}){
            int rate=44100,frames=19001,format=bits==32?3:1;File source=new File(dir,"original-"+channels+"-"+bits+".wav"),target=new File(dir,"clip-"+channels+"-"+bits+".wav");byte[] samples=new byte[frames*channels*(bits/8)];random.nextBytes(samples);
            try(RandomAccessFile out=new RandomAccessFile(source,"rw")){out.setLength(0);PcmFile.header(out,frames,rate,channels,bits,format);out.write(samples);if((samples.length&1)!=0)out.write(0);}
            byte[] original=Files.readAllBytes(source.toPath());double a=73.125,b=319.875;long first=Math.round(a*rate/1000),last=Math.round(b*rate/1000);AudioClip.save(source,target,a,b);
            try(PcmFile pcm=new PcmFile(target)){check(pcm.rate==rate&&pcm.channels==channels&&pcm.bits==bits&&pcm.format==format,"excerpt preserves PCM format, rate and all channel lanes");check(pcm.frames==last-first,"excerpt is aligned to whole sample frames");}
            check(Arrays.equals(data(target),Arrays.copyOfRange(samples,(int)first*channels*(bits/8),(int)last*channels*(bits/8))),"excerpt PCM is byte-for-byte identical to the selected source frames");
            check(Arrays.equals(original,Files.readAllBytes(source.toPath())),"original recording remains unchanged");
            AudioClip.save(source,target,0,frames*1000.0/rate);check(Arrays.equals(samples,data(target)),"full-duration excerpt keeps the final frame");
        }
        File mono=new File(dir,"odd-8bit.wav"),odd=new File(dir,"odd-clip.wav");try(RandomAccessFile out=new RandomAccessFile(mono,"rw")){PcmFile.header(out,100,8000,1,8,1);out.write(new byte[100]);}AudioClip.save(mono,odd,0,.125);try(PcmFile pcm=new PcmFile(odd)){check(pcm.frames==1&&odd.length()==46,"odd-sized 8-bit excerpts include RIFF padding without an extra sample");}
        File source=new File(dir,"original-2-16.wav"),target=new File(dir,"preserved.wav");Files.write(target.toPath(),"keep existing output".getBytes("UTF-8"));
        for(double[] invalid:new double[][]{{-1,10},{20,20},{20,10},{0,999999},{Double.NaN,10},{0,Double.POSITIVE_INFINITY},{0,.000001}})rejected(source,target,invalid[0],invalid[1]);
        byte[] original=Files.readAllBytes(source.toPath());try{AudioClip.save(source,source,0,10);throw new AssertionError("source overwritten");}catch(IOException expected){check(Arrays.equals(original,Files.readAllBytes(source.toPath())),"same-path save never overwrites source");}
        try{AudioClip.save(source,new File(dir,"./original-2-16.wav"),0,10);throw new AssertionError("alias overwritten");}catch(IOException expected){checks++;}
        byte[] previous=Files.readAllBytes(target.toPath());boolean cancelled=false;Thread.currentThread().interrupt();try{AudioClip.save(source,target,0,10);throw new AssertionError("cancel ignored");}catch(InterruptedIOException expected){cancelled=true;}finally{Thread.interrupted();}check(cancelled&&Arrays.equals(previous,Files.readAllBytes(target.toPath())),"cancellation preserves existing output");
        try{AudioClip.saveAtomically(target,tmp->{Files.write(tmp.toPath(),new byte[600]);throw new IOException("simulated failure");});throw new AssertionError("writer failure ignored");}catch(IOException expected){check(Arrays.equals(previous,Files.readAllBytes(target.toPath())),"failure after writing temporary audio preserves destination");}
        rejected(new File(dir,"missing.wav"),target,0,10);check(Arrays.stream(dir.listFiles()).noneMatch(f->f.getName().endsWith(".part")),"failed, cancelled and successful saves leave no partial files");
        File left=new File(dir,"left-11025.wav"),right=new File(dir,"right-48000.wav");float[] a=new float[11025],b=new float[48000];for(int i=0;i<a.length;i++)a[i]=(float)Math.sin(i*.31)*.5f;for(int i=0;i<b.length;i++)b[i]=(float)Math.sin(i*.51)*.3f;PcmFile.write(left,a,11025);PcmFile.write(right,b,48000);
        List<File> tracks=Arrays.asList(left,right,left);List<Double> offsets=Arrays.asList(0.0,89.375,200.0);File full=new File(dir,"full-directions.wav"),clip=new File(dir,"clip-directions.wav"),reference=new File(dir,"reference-directions.wav");PcmTracks.separate(tracks,offsets,full);
        for(double[] range:new double[][]{{0,50},{73.125,670.375},{1000,1199.5}}){PcmTracks.separateRange(tracks,offsets,clip,range[0],range[1]);AudioClip.save(full,reference,range[0],range[1]);check(Arrays.equals(data(clip),data(reference)),"direct RTP excerpt equals the same interval of a complete multi-channel export, including resampling and fractional offsets");}
        PcmTracks.separateRange(Collections.nCopies(64,right),Collections.nCopies(64,3599000.0),clip,3599000,3599100);try(PcmFile pcm=new PcmFile(clip)){check(pcm.channels==64&&pcm.frames==4800,"short excerpt works even when the complete 64-channel timeline would exceed RIFF size");}
        System.out.println("PASS: "+checks+" audio excerpt checks; exact PCM, timelines, channels and safe writes");return checks;
    }
    public static void main(String[] args)throws Exception{run(new File(args[0]));}
}
