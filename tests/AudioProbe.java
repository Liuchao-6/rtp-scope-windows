package com.liuchao.rtpscope.desktop;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** Opens and seeks a clip without starting playback; audible output still needs manual testing. */
public final class AudioProbe {
    public static void main(String[] args)throws Exception {
        WavPlayer player=new WavPlayer();String result;
        try{player.load(new File(args[0]));player.seek(40);if(player.duration()<100||player.position()<35)throw new IllegalStateException("Unexpected audio duration/seek");result="PASS: Windows default audio clip opened, duration="+player.duration()+" ms, seek="+player.position()+" ms; playback not started\n";}
        catch(Exception e){result="UNAVAILABLE: "+Ui.error(e)+"; real output needs manual testing\n";}
        finally{player.close();}
        Files.write(new File(args[1]).toPath(),result.getBytes(StandardCharsets.UTF_8));System.out.print(result);
    }
}
