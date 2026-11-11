package org.jitsi.impl.neomedia.codec.audio.g729;

import java.io.*;

/** Encodes only generated demo PCM; never included in the application. */
public final class DemoAudioFixture {
    public static void main(String[] args)throws Exception {
        Coder coder=new Coder();short[] pcm=new short[80],serial=new short[82];
        try(InputStream in=new BufferedInputStream(new FileInputStream(args[0]));OutputStream out=new FileOutputStream(args[1])) {
            while(true){int first=in.read();if(first<0)break;int next=in.read();if(next<0)throw new EOFException();pcm[0]=(short)(first|(next<<8));
                for(int n=1;n<80;n++){int lo=in.read(),hi=in.read();if(lo<0||hi<0)throw new EOFException();pcm[n]=(short)(lo|(hi<<8));}
                coder.process(pcm,serial);
                for(int n=0;n<10;n++){int value=0;for(int bit=0;bit<8;bit++)value=(value<<1)|(serial[2+n*8+bit]==Ld8k.BIT_1?1:0);out.write(value);}
            }
        }
    }
}
