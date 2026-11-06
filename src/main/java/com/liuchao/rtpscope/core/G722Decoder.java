package com.liuchao.rtpscope.core;
/**
 * G.722 64 kbit/s decoder port of Steve Underwood's public-domain SpanDSP decoder.
 * Copyright (C) 2005 Steve Underwood. Based on CMU ADPCM, Copyright CMU 1993,
 * Chengxiang Lu and Alex Hauptmann; research/commercial use unrestricted.
 * See licenses/g722-LICENSE.txt for the original attribution and dedication.
 */
final class G722Decoder {
    private static final class Band {int s,sp,sz,nb,det;int[] r=new int[3],a=new int[3],ap=new int[3],p=new int[3],d=new int[7],b=new int[7],bp=new int[7],sg=new int[7];}
    private final Band[] band={new Band(),new Band()};private final int[] x=new int[24];
    G722Decoder(){band[0].det=32;band[1].det=8;}
    private static int saturate(int value){return Math.max(-32768,Math.min(32767,value));}
    private static final int[] wl={-60, -30, 58, 172, 334, 538, 1198, 3042 };
    private static final int[] rl42={0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3,  2, 1, 0 };
    private static final int[] ilb={
        2048, 2093, 2139, 2186, 2233, 2282, 2332,
        2383, 2435, 2489, 2543, 2599, 2656, 2714,
        2774, 2834, 2896, 2960, 3025, 3091, 3158,
        3228, 3298, 3371, 3444, 3520, 3597, 3676,
        3756, 3838, 3922, 4008
    };
    private static final int[] wh={0, -214, 798};
    private static final int[] rh2={2, 1, 2, 1};
    private static final int[] qm2={-7408, -1616,  7408,   1616};
    private static final int[] qm4={
              0, -20456, -12896,  -8968, 
          -6288,  -4240,  -2584,  -1200,
          20456,  12896,   8968,   6288,
           4240,   2584,   1200,      0
    };
    private static final int[] qm6={
           -136,   -136,   -136,   -136,
         -24808, -21904, -19008, -16704,
         -14984, -13512, -12280, -11192,
         -10232,  -9360,  -8576,  -7856,
          -7192,  -6576,  -6000,  -5456,
          -4944,  -4464,  -4008,  -3576,
          -3168,  -2776,  -2400,  -2032,
          -1688,  -1360,  -1040,   -728,
          24808,  21904,  19008,  16704,
          14984,  13512,  12280,  11192,
          10232,   9360,   8576,   7856,
           7192,   6576,   6000,   5456,
           4944,   4464,   4008,   3576,
           3168,   2776,   2400,   2032,
           1688,   1360,   1040,    728,
            432,    136,   -432,   -136
    };
    private static final int[] qmf_coeffs={
           3,  -11,   12,   32, -210,  951, 3876, -805,  362, -156,   53,  -11,
    };
    private static void block4(Band band,int d){
    int wd1;
    int wd2;
    int wd3;
    int i;

    /* Block 4, RECONS */
    band.d[0] = d;
    band.r[0] = saturate(band.s + d);

    /* Block 4, PARREC */
    band.p[0] = saturate(band.sz + d);

    /* Block 4, UPPOL2 */
    for (i = 0;  i < 3;  i++)
        band.sg[i] = band.p[i] >> 15;
    wd1 = saturate(band.a[1] << 2);

    wd2 = (band.sg[0] == band.sg[1])  ?  -wd1  :  wd1;
    if (wd2 > 32767)
        wd2 = 32767;
    wd3 = (wd2 >> 7) + ((band.sg[0] == band.sg[2])  ?  128  :  -128);
    wd3 += (band.a[2]*32512) >> 15;
    if (wd3 > 12288)
        wd3 = 12288;
    else if (wd3 < -12288)
        wd3 = -12288;
    band.ap[2] = wd3;

    /* Block 4, UPPOL1 */
    band.sg[0] = band.p[0] >> 15;
    band.sg[1] = band.p[1] >> 15;
    wd1 = (band.sg[0] == band.sg[1])  ?  192  :  -192;
    wd2 = (band.a[1]*32640) >> 15;

    band.ap[1] = saturate(wd1 + wd2);
    wd3 = saturate(15360 - band.ap[2]);
    if (band.ap[1] > wd3)
        band.ap[1] = wd3;
    else if (band.ap[1] < -wd3)
        band.ap[1] = -wd3;

    /* Block 4, UPZERO */
    wd1 = (d == 0)  ?  0  :  128;
    band.sg[0] = d >> 15;
    for (i = 1;  i < 7;  i++)
    {
        band.sg[i] = band.d[i] >> 15;
        wd2 = (band.sg[i] == band.sg[0])  ?  wd1  :  -wd1;
        wd3 = (band.b[i]*32640) >> 15;
        band.bp[i] = saturate(wd2 + wd3);
    }

    /* Block 4, DELAYA */
    for (i = 6;  i > 0;  i--)
    {
        band.d[i] = band.d[i - 1];
        band.b[i] = band.bp[i];
    }
    
    for (i = 2;  i > 0;  i--)
    {
        band.r[i] = band.r[i - 1];
        band.p[i] = band.p[i - 1];
        band.a[i] = band.ap[i];
    }

    /* Block 4, FILTEP */
    wd1 = saturate(band.r[1] + band.r[1]);
    wd1 = (band.a[1]*wd1) >> 15;
    wd2 = saturate(band.r[2] + band.r[2]);
    wd2 = (band.a[2]*wd2) >> 15;
    band.sp = saturate(wd1 + wd2);

    /* Block 4, FILTEZ */
    band.sz = 0;
    for (i = 6;  i > 0;  i--)
    {
        wd1 = saturate(band.d[i] + band.d[i]);
        band.sz += (band.b[i]*wd1) >> 15;
    }
    band.sz = saturate(band.sz);

    /* Block 4, PREDIC */
    band.s = saturate(band.sp + band.sz);

    }
    short[] decode(byte[] input){
        short[] out=new short[input.length*2];int n=0;
        for(byte value:input){
            int code=value&255,low=code&63,high=(code>>>6)&3;
            int quantized=(band[0].det*qm6[low])>>15;
            int rlow=Math.max(-16384,Math.min(16383,band[0].s+quantized));
            low>>=2;int dlow=(band[0].det*qm4[low])>>15;
            band[0].nb=Math.max(0,Math.min(18432,((band[0].nb*127)>>7)+wl[rl42[low]]));
            int index=(band[0].nb>>6)&31,shift=8-(band[0].nb>>11);
            band[0].det=(shift<0?ilb[index]<<-shift:ilb[index]>>shift)<<2;block4(band[0],dlow);
            int dhigh=(band[1].det*qm2[high])>>15;
            int rhigh=Math.max(-16384,Math.min(16383,dhigh+band[1].s));
            band[1].nb=Math.max(0,Math.min(22528,((band[1].nb*127)>>7)+wh[rh2[high]]));
            index=(band[1].nb>>6)&31;shift=10-(band[1].nb>>11);
            band[1].det=(shift<0?ilb[index]<<-shift:ilb[index]>>shift)<<2;block4(band[1],dhigh);
            System.arraycopy(x,2,x,0,22);x[22]=rlow+rhigh;x[23]=rlow-rhigh;
            int first=0,second=0;for(int i=0;i<12;i++){second+=x[2*i]*qmf_coeffs[i];first+=x[2*i+1]*qmf_coeffs[11-i];}
            out[n++]=(short)saturate(first>>11);out[n++]=(short)saturate(second>>11);
        }return out;
    }
}
