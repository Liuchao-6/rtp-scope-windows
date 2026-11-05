package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.util.function.Consumer;
import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;

public final class SipDetailPanel extends JPanel {
    private final JLabel title=Ui.label("报文详情",16,Ui.INK);
    private final JTextArea metadata=Ui.note("点击流序图箭头或列表中的消息，查看完整内容");
    private final RawPane raw=new RawPane();
    private String original="";
    private Consumer<String> status;
    public SipDetailPanel() {
        super(new BorderLayout(Ui.u(8),Ui.u(6)));setBackground(Ui.PANEL);setBorder(BorderFactory.createEmptyBorder(Ui.u(10),Ui.u(10),Ui.u(10),Ui.u(10)));
        JPanel top=new JPanel(new BorderLayout(0,Ui.u(6)));top.add(title,BorderLayout.NORTH);metadata.setRows(3);top.add(metadata,BorderLayout.CENTER);
        JPanel tools=new JPanel(new FlowLayout(FlowLayout.LEFT,Ui.u(5),0));JButton copy=Ui.button("复制原文",false);JCheckBox wrap=new JCheckBox("自动换行",true);wrap.setFocusPainted(false);
        tools.add(copy);tools.add(wrap);top.add(tools,BorderLayout.SOUTH);add(top,BorderLayout.NORTH);
        copy.addActionListener(e->{try{Ui.copy(original);if(status!=null)status.accept("已复制原始文本");}catch(IllegalStateException ex){if(status!=null)status.accept("剪贴板正忙，请稍后重试");}});
        wrap.addActionListener(e->{raw.wrap=wrap.isSelected();raw.revalidate();raw.repaint();});
        raw.setEditable(false);raw.setBackground(new Color(0xfafbfd));raw.setForeground(Ui.INK);raw.setCaretColor(Ui.INK);raw.setFont(new Font(Font.MONOSPACED,Font.PLAIN,Ui.u(13)));
        raw.setMargin(new Insets(Ui.u(12),Ui.u(12),Ui.u(12),Ui.u(12)));add(Ui.scroll(raw),BorderLayout.CENTER);
        JPanel legend=new JPanel(new FlowLayout(FlowLayout.LEFT,Ui.u(7),0));String[] names={"方法","头字段","URI","标识符","SDP"};SipSyntax.Kind[] kinds={SipSyntax.Kind.METHOD,SipSyntax.Kind.HEADER,SipSyntax.Kind.URI,SipSyntax.Kind.ID,SipSyntax.Kind.SDP};
        for(int i=0;i<names.length;i++)legend.add(Ui.label(names[i],11,Ui.syntaxColor(kinds[i])));add(legend,BorderLayout.SOUTH);
    }
    public void setStatusListener(Consumer<String> listener){status=listener;}
    public void showSip(SipMessage message) {
        title.setText(CallFlow.sipTitle(message));metadata.setText("时间："+Ui.stamp(message.timeUs)+"  ·  "+message.transport+"\n源："+message.src+"\n目的："+message.dst);metadata.setToolTipText("CSeq："+message.cseq+"  ·  Call-ID："+message.callId);
        setRaw(message.raw,true);
    }
    public void showText(String heading,String context,String content){title.setText(heading);metadata.setText(context);setRaw(content,false);}
    public String original(){return original;}
    public StyledDocument document(){return raw.getStyledDocument();}
    private void setRaw(String value,boolean sip) {
        original=value;StyledDocument doc=raw.getStyledDocument();
        try {
            doc.remove(0,doc.getLength());SimpleAttributeSet normal=new SimpleAttributeSet();StyleConstants.setForeground(normal,Ui.INK);StyleConstants.setFontFamily(normal,Font.MONOSPACED);StyleConstants.setFontSize(normal,Ui.u(13));
            doc.insertString(0,value,normal);
            if(sip)for(SipSyntax.Span span:SipSyntax.spans(value)){SimpleAttributeSet style=new SimpleAttributeSet();StyleConstants.setForeground(style,Ui.syntaxColor(span.kind));if(span.kind==SipSyntax.Kind.HEADER||span.kind==SipSyntax.Kind.METHOD)StyleConstants.setBold(style,true);doc.setCharacterAttributes(span.start,span.end-span.start,style,false);}
            raw.setCaretPosition(0);
        }catch(BadLocationException e){throw new IllegalStateException(e);}
    }
    private static final class RawPane extends JTextPane {
        boolean wrap=true;
        public boolean getScrollableTracksViewportWidth(){return wrap||getParent()==null||getUI().getPreferredSize(this).width<=getParent().getWidth();}
    }
}
