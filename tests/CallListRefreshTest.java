package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.concurrent.atomic.*;
import javax.swing.*;

/** Large call lists must not lay out every offscreen row when a filter changes. */
public final class CallListRefreshTest {
    private static int checks;
    private static void check(boolean condition,String message){checks++;if(!condition)throw new AssertionError(message);}
    private static Component find(Container parent,String name){for(Component child:parent.getComponents()){if(name.equals(child.getName()))return child;if(child instanceof Container){Component result=find((Container)child,name);if(result!=null)return result;}}return null;}
    public static int run()throws Exception {
        Analysis analysis=new Analysis();int total=20000;
        for(int n=0;n<total;n++){Call call=new Call();call.id="synthetic-call-"+n;call.from="<sip:1001@example.test>";call.to="<sip:1002@example.test>";call.requestTarget="sip:1002@example.test";call.status="SIP/2.0 200 OK";call.sipCount=4;call.startUs=1793851200000000L+n*1000000L;call.lastUs=call.startUs+30000000;analysis.calls.add(call);}
        AtomicReference<Throwable> error=new AtomicReference<>();AtomicLong renders=new AtomicLong();long start=System.nanoTime();
        SwingUtilities.invokeAndWait(()->{DesktopApp app=new DesktopApp();try{
            JList<Call> list=(JList<Call>)find(app,"calls");ListCellRenderer<? super Call> original=list.getCellRenderer();
            list.setCellRenderer((view,value,index,selected,focus)->{renders.incrementAndGet();return original.getListCellRendererComponent(view,value,index,selected,focus);});
            app.acceptAnalysis(analysis,"合成 · 2 万通话");list.getPreferredSize();
            check(app.callCount()==total&&list.getModel().getSize()==total,"large import keeps every call");
            list.setSelectedIndex(19999);CallSearch.Filter filter=new CallSearch.Filter();filter.caller="1001";app.setCallSearch(filter);list.getPreferredSize();
            check(app.callCount()==total&&list.getSelectedValue().id.equals("synthetic-call-19999"),"filter preserves selected call by identity");
            filter.keyword="synthetic-call-19999";app.setCallSearch(filter);
            check(app.callCount()==1&&list.getSelectedValue().id.equals("synthetic-call-19999"),"exact call lookup and selection survive list replacement");
            app.setCallSearch(new CallSearch.Filter());list.getPreferredSize();
            check(app.callCount()==total&&list.getSelectedIndex()==19999,"clearing filters restores all calls and selection");
            JTextField quick=(JTextField)find(app,"callQuickSearch");quick.setText("does-not-exist");check(app.callCount()==0,"real quick-search field handles an empty large result");
            quick.setText("synthetic-call-19999");check(app.callCount()==1,"quick-search field restores matching call");quick.setText("");
            check(app.callCount()==total&&app.model.callId.equals("synthetic-call-19999"),"typing does not select a different call");
            check(renders.get()<100,"refresh avoids formatting thousands of offscreen calls; renders="+renders.get());
            list.clearSelection();list.setSize(220,total*122);BufferedImage image=new BufferedImage(220,600,BufferedImage.TYPE_INT_RGB);Graphics2D graphics=image.createGraphics();graphics.setClip(0,0,220,600);list.paint(graphics);graphics.dispose();
            check(renders.get()>0&&renders.get()<100,"painting renders only viewport rows");
            list.setSelectedIndex(total-1);check(list.getSelectedValue().id.equals("synthetic-call-19999"),"last call remains accessible after scrolling layout");
        }catch(Throwable failure){error.set(failure);}finally{app.shutdown();}});
        if(error.get()!=null)throw new AssertionError("Large call-list refresh regression",error.get());
        System.out.println("Large call-list UI: "+total+" calls; renderer calls="+renders.get()+"; elapsed="+(System.nanoTime()-start)/1000000+" ms");return checks;
    }
}
