import java.util.*;
import com.liuchao.rtpscope.core.CaptureWorkspace;

public final class CaptureWorkspaceTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    public static int run(){
        CaptureWorkspace<String> files=new CaptureWorkspace<>();
        check(files.size()==0&&files.activeIndex()==-1&&files.current()==null,"empty workspace");
        check(files.add("one","通话.pcap","source one")==0,"first source index");
        check(files.add("two","通话.pcap","source two")==1,"same display name is independent source");
        check(files.current()==null,"registration never starts analysis");files.select(0);
        files.current().query="INVITE";files.current().callId="same-call-id";files.current().tab=1;files.current().sipList=true;
        check(files.label(0).equals("1 / 2 · 通话.pcap"),"file position and count visible");
        check(files.add("one","duplicate selection","replacement")==0&&files.size()==2,"duplicate identity not added twice");
        check(files.current().source.equals("source one")&&files.current().query.equals("INVITE"),"duplicate import retains source and view");
        files.select(1);check(files.current().query.isEmpty()&&files.current().callId.isEmpty()&&!files.current().sipList,"new source has independent filters");
        files.current().error="damaged header";check(files.current().toString().contains("导入失败"),"failure marked on only affected file");
        files.select(0);check(files.current().query.equals("INVITE")&&files.current().callId.equals("same-call-id")&&files.current().tab==1&&files.current().sipList,"switch restores per-file state");
        check(files.current().error.isEmpty(),"other source unaffected by failure");
        try{files.select(8);throw new AssertionError("invalid selection accepted");}catch(IndexOutOfBoundsException expected){check(files.activeIndex()==0,"invalid selection leaves active source intact");}
        files.removeCurrent();check(files.size()==1&&files.activeIndex()==0&&files.current().id.equals("two"),"close selects remaining file");
        files.add("three","第三个.pcapng","third");files.select(1);files.removeCurrent();check(files.activeIndex()==0&&files.current().id.equals("two"),"close last selects previous file");
        files.removeCurrent();check(files.size()==0&&files.activeIndex()==-1&&files.current()==null,"closing all empties workspace");files.removeCurrent();
        files.add("empty-name",null,null);check(files.get(0).name.equals("本地抓包"),"unnamed source fallback");
        try{files.add("","bad",null);throw new AssertionError("empty source id accepted");}catch(IllegalArgumentException expected){checks++;}
        return checks;
    }
}
