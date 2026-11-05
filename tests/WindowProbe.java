package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import com.liuchao.rtpscope.core.CaptureEngine;
import com.liuchao.rtpscope.core.CaptureEngine.Analysis;

/** Creates and validates a real hidden native window, then disposes it without desktop input. */
public final class WindowProbe {
    public static void main(String[] args)throws Exception {
        final Analysis demo;try(InputStream in=WindowProbe.class.getResourceAsStream("/demo-analysis.pcap")){demo=CaptureEngine.read(in);}
        SwingUtilities.invokeAndWait(()->{
            Ui.setup();DesktopApp app=new DesktopApp();JFrame frame=new JFrame("超哥话探 · 启动检查");
            try {
                frame.setContentPane(app);Ui.fitWindow(frame,1450,920,1040,700);frame.addNotify();frame.validate();app.acceptAnalysis(demo,"启动检查");app.openEntry(demo.sip.get(0));frame.validate();
                if(!frame.isDisplayable()||app.isPlayerExpanded()||app.getWidth()<500||app.flow.data().entries.size()!=8||!app.detail.original().equals(demo.sip.get(0).raw))throw new AssertionError("Native window initialization failed");
                String result="PASS: native hidden JFrame initialized; os="+System.getProperty("os.name")+"; dpi_scale="+Ui.SCALE+"; size="+frame.getWidth()+"x"+frame.getHeight()+"; demo=8 entries; SIP detail exact\n";
                try{Files.write(new File(args[0]).toPath(),result.getBytes(StandardCharsets.UTF_8));}catch(IOException e){throw new RuntimeException(e);}System.out.print(result);
            }finally{app.shutdown();frame.dispose();}
        });
    }
}
