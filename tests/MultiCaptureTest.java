package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.io.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import com.liuchao.rtpscope.core.CaptureEngine.*;

public final class MultiCaptureTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void ready(DesktopApp app)throws Exception{
        for(int i=0;i<300;i++){AtomicReference<Boolean> busy=new AtomicReference<>();SwingUtilities.invokeAndWait(()->busy.set((app.isBusy()||app.isBackgroundWorking())));if(!busy.get())return;Thread.sleep(30);}
        throw new AssertionError("capture background task timed out");
    }
    private static Component find(Container parent,String name){for(Component child:parent.getComponents()){if(name.equals(child.getName()))return child;if(child instanceof Container){Component found=find((Container)child,name);if(found!=null)return found;}}return null;}
    private static void layout(Container parent){parent.doLayout();for(Component child:parent.getComponents())if(child instanceof Container)layout((Container)child);}
    public static int run(File fixtures,File out)throws Exception{
        AtomicReference<DesktopApp> reference=new AtomicReference<>();
        File one=new File(fixtures,"demo-analysis.pcap"),two=new File(fixtures,"key-modes.pcap"),bad=new File(fixtures,"invalid.pcap"),partial=new File(fixtures,"truncated.pcap");
        SwingUtilities.invokeAndWait(()->{DesktopApp app=new DesktopApp();reference.set(app);app.setSize(Ui.u(1450),Ui.u(920));layout(app);layout(app);app.loadFiles(Arrays.asList(one,two,bad,partial,one));});DesktopApp app=reference.get();
        try{
            ready(app);final Analysis[] first={null};final File[] wav={null};
            SwingUtilities.invokeAndWait(()->{check(app.captureCount()==4&&app.captureIndex()==0,"multi import deduplicates file paths");first[0]=app.model.analysis;check(first[0]!=null&&first[0].events.size()==1,"only selected capture is analyzed");app.setSearch("INVITE");app.model.callId=first[0].calls.get(0).id;((JTabbedPane)find(app,"analysisTabs")).setSelectedIndex(1);List<RtpStream> audio=new ArrayList<>();for(RtpStream stream:first[0].streams)if(stream.playable())audio.add(stream);app.previewAudio(audio);});
            ready(app);SwingUtilities.invokeAndWait(()->{wav[0]=app.renderedFile();check(wav[0]!=null&&wav[0].isFile(),"first capture has audio preview before switch");app.model.selected.add(first[0].streams.get(0));JComboBox<?> selector=(JComboBox<?>)find(app,"captureFiles");check(selector!=null&&selector.getItemCount()==4,"real file selector lists each source");selector.setSelectedIndex(1);check(app.model.analysis==null&&app.renderedFile()==null&&app.waveform.preview()==null,"switch clears previous capture and waveform immediately");check(app.model.selected.isEmpty()&&!app.isPlayerExpanded()&&!selector.isEnabled(),"stale selections cleared and switch disabled while loading");});
            ready(app);SwingUtilities.invokeAndWait(()->{check(!wav[0].exists(),"switch deletes old temporary WAV");check(app.captureIndex()==1&&app.model.analysis!=null&&app.model.analysis.events.size()>first[0].events.size(),"second capture has independent key analysis");check(app.model.query.isEmpty()&&app.model.callId.isEmpty(),"second capture starts without first capture filters");app.setSearch("SIP INFO");layout(app);layout(app);check(((JList<?>)find(app,"calls")).getModel().getSize()==1&&find(app,"calls").getHeight()>=Ui.u(100),"multi file layout retains visible call list");try{java.awt.image.BufferedImage image=new java.awt.image.BufferedImage(app.getWidth(),app.getHeight(),java.awt.image.BufferedImage.TYPE_INT_RGB);Graphics2D graphics=image.createGraphics();app.printAll(graphics);graphics.dispose();javax.imageio.ImageIO.write(image,"png",new File(out,"windows-multi-capture.png"));}catch(IOException e){throw new RuntimeException(e);}app.selectCapture(2);});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.analysis==null&&app.flow.data().entries.isEmpty()&&app.detail.original().contains("切换其他抓包"),"invalid file never shows another capture results");check(app.captureCount()==4&&((JComboBox<?>)find(app,"captureFiles")).isEnabled(),"one failed file leaves other captures accessible");app.selectCapture(0);});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.analysis.sip.size()==first[0].sip.size()&&app.model.analysis.events.size()==1,"return to first capture does not merge SIP or keys");check(app.model.query.equals("INVITE")&&app.model.callId.equals(first[0].calls.get(0).id),"per-file search and call filters restored");check(((JTabbedPane)find(app,"analysisTabs")).getSelectedIndex()==1,"each file restores its selected page");app.selectCapture(1);});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.query.equals("SIP INFO")&&app.model.events().size()==4,"second file remembers its own search");app.selectCapture(3);});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.analysis.partial&&app.model.analysis.packets>0,"partial capture still imports in multi-file mode");((JButton)find(app,"closeCapture")).doClick();});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.captureCount()==3&&app.captureIndex()==2,"closing current selects adjacent file");((JButton)find(app,"closeCapture")).doClick();});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.analysis!=null&&app.model.query.equals("SIP INFO"),"closing failed file returns to valid capture");((JButton)find(app,"closeCapture")).doClick();});
            ready(app);SwingUtilities.invokeAndWait(()->{((JButton)find(app,"closeCapture")).doClick();check(app.captureCount()==0&&app.model.analysis==null&&app.flow.data().entries.isEmpty(),"closing all captures clears analysis");check(one.isFile()&&two.isFile()&&bad.isFile()&&partial.isFile(),"closing entries preserves original captures");
                Transferable transfer=new Transferable(){public DataFlavor[] getTransferDataFlavors(){return new DataFlavor[]{DataFlavor.javaFileListFlavor};}public boolean isDataFlavorSupported(DataFlavor flavor){return flavor.equals(DataFlavor.javaFileListFlavor);}public Object getTransferData(DataFlavor flavor){return Arrays.asList(one,two);}};
                check(app.getTransferHandler().importData(new TransferHandler.TransferSupport(app,transfer)),"drop accepts multiple files");});
            ready(app);SwingUtilities.invokeAndWait(()->check(app.captureCount()==2&&app.model.analysis.events.size()==1,"drop registers all sources and opens first independently"));
        }finally{SwingUtilities.invokeAndWait(app::shutdown);}
        return checks;
    }
}
