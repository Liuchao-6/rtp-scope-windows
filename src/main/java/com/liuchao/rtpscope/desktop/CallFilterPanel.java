package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import com.liuchao.rtpscope.core.CallSearch;

/** Compact structured call search; no packet-search state is changed here. */
public final class CallFilterPanel extends JPanel {
    private final JTextField keyword=new JTextField(),caller=new JTextField(),callee=new JTextField(),ip=new JTextField(),start=new JTextField(),end=new JTextField();
    public CallFilterPanel(CallSearch.Filter initial){
        super(new BorderLayout(0,Ui.u(10)));JPanel fields=new JPanel(new GridLayout(0,2,Ui.u(12),Ui.u(9)));
        String[] labels={"关键字 / Call-ID","主叫号码（支持部分号码）","被叫号码（支持部分号码）","信令或媒体 IP（支持部分地址）","开始时间","结束时间"};
        JTextField[] inputs={keyword,caller,callee,ip,start,end};String[] values={initial.keyword,initial.caller,initial.callee,initial.ip,initial.start,initial.end};
        for(int n=0;n<inputs.length;n++){fields.add(Ui.label(labels[n],13,Ui.INK));inputs[n].setText(values[n]);inputs[n].setColumns(25);inputs[n].setName(new String[]{"keyword","caller","callee","ip","start","end"}[n]);fields.add(inputs[n]);}
        add(fields,BorderLayout.CENTER);add(Ui.note("所有条件同时匹配；号码和 IP 可以只填一部分。\n时间格式：14:30:00 或 2026-11-05 14:30:00，可加 .123 毫秒。\n按通话时间段是否重叠筛选；只填时分秒时可跨午夜。\n本机时区："+TimeZone.getDefault().getID()),BorderLayout.SOUTH);
    }
    public CallSearch.Filter value(){CallSearch.Filter f=new CallSearch.Filter();f.keyword=keyword.getText().trim();f.caller=caller.getText().trim();f.callee=callee.getText().trim();f.ip=ip.getText().trim();f.start=start.getText().trim();f.end=end.getText().trim();CallSearch.find(Collections.emptyList(),f);return f;}
}
