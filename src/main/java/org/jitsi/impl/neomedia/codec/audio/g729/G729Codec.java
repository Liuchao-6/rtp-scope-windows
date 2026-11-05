package org.jitsi.impl.neomedia.codec.audio.g729;

import java.io.IOException;

/** Project-owned RTP adapter; upstream codec files are preserved unchanged. */
public final class G729Codec {
    private Decoder decoder=new Decoder();
    private final short[] serial=new short[82], pcm=new short[80];
    public short[] decode(byte[] payload) throws IOException {
        int remainder=payload.length%10;
        if(payload.length==0 || (remainder!=0&&remainder!=2))throw new IOException("G.729 包长应为 N×10 字节，可附加 2 字节 SID");
        short[] samples=new short[(payload.length/10+(remainder==2?1:0))*80];
        for(int offset=0;offset+10<=payload.length;offset+=10) {
            serial[0]=Ld8k.SYNC_WORD;serial[1]=80;
            for(int bit=0;bit<80;bit++)serial[bit+2]=((payload[offset+bit/8]>>(7-bit%8))&1)==0?Ld8k.BIT_0:Ld8k.BIT_1;
            decoder.process(serial,pcm);System.arraycopy(pcm,0,samples,offset/10*80,80);
        }
        // Annex B comfort noise is not synthesized. Its 10 ms SID interval remains silent.
        if(remainder==2)reset();
        return samples;
    }
    public void advanceLoss(int frames) {
        if(frames>100){reset();return;}
        for(int frame=0;frame<frames;frame++) {
            java.util.Arrays.fill(serial,(short)0);serial[0]=Ld8k.SYNC_WORD;serial[1]=80;
            decoder.process(serial,pcm);
        }
    }
    public void reset(){decoder=new Decoder();}
}
