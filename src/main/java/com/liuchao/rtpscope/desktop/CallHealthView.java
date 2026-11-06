package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import javax.swing.*;
import java.awt.*;
import java.util.function.Consumer;

/** Native overview cards, with evidence controls in the same scrollable surface. */
final class CallHealthView extends JPanel implements Scrollable {
    private final Consumer<Object> open;
    CallHealthView(Consumer<Object> open){this.open=open;setLayout(new BoxLayout(this,BoxLayout.Y_AXIS));setBackground(Ui.BG);setBorder(BorderFactory.createEmptyBorder(Ui.u(18),Ui.u(18),Ui.u(18),Ui.u(18)));}
    private void section(JComponent c){c.setAlignmentX(LEFT_ALIGNMENT);c.setMaximumSize(new Dimension(Integer.MAX_VALUE,c.getPreferredSize().height));add(c);add(Box.createVerticalStrut(Ui.u(12)));}
    private JPanel vertical(){JPanel p=new JPanel();p.setOpaque(false);p.setLayout(new BoxLayout(p,BoxLayout.Y_AXIS));return p;}
    private void line(JPanel p,String text,int size,Color color){JLabel label=Ui.label(text,size,color);label.setAlignmentX(LEFT_ALIGNMENT);p.add(label);p.add(Box.createVerticalStrut(Ui.u(4)));}
    void showHealth(CallHealth health){
        removeAll();if(health==null){section(Ui.label("先选择一通电话",22,Ui.INK));section(Ui.label("体检显示通话时间、结束方、信令与媒体证据。",13,Ui.MUTED));revalidate();repaint();return;}
        JPanel title=vertical();line(title,"通话概览",22,Ui.INK);line(title,CallSearch.participants(health.call),12,Ui.MUTED);section(title);
        JPanel overview=Ui.card(new BorderLayout(0,Ui.u(12)));JPanel metrics=new JPanel(new GridLayout(1,4,Ui.u(16),0));metrics.setOpaque(false);
        metrics.add(metric("通话时长",CallHealth.duration(health.durationUs()),"接通至首次 BYE"));metrics.add(metric("接通等待",CallHealth.duration(health.startUs>=0&&health.answerUs>=health.startUs?health.answerUs-health.startUs:-1),"首次 INVITE 至成功响应"));metrics.add(metric("结束方",health.endSide,"当前通话段所见"));metrics.add(metric("通话状态",health.state,"以 SIP 信令为依据"));overview.add(metrics,BorderLayout.NORTH);
        JPanel moments=new JPanel(new GridLayout(1,3,Ui.u(18),0));moments.setOpaque(false);moments.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createMatteBorder(Ui.u(1),0,0,0,Ui.LINE),BorderFactory.createEmptyBorder(Ui.u(12),0,0,0)));
        moments.add(moment("呼叫开始",health.startUs));moments.add(moment("接通时间",health.answerUs));moments.add(moment("结束时间",health.endUs));overview.add(moments,BorderLayout.CENTER);section(overview);
        JPanel ending=Ui.card(new GridLayout(1,2,Ui.u(18),0));JPanel evidence=vertical(),reason=vertical();line(evidence,"结束依据",11,Ui.MUTED);
        if(health.end==null){line(evidence,"结束未捕获",15,Ui.INK);line(reason,"完整时长与挂断方未知",13,Ui.MUTED);line(reason,"最后观测："+CallHealth.time(health.lastUs),11,Ui.MUTED);}
        else {line(evidence,health.endSide+" · "+(CallHealth.method(health.end).isEmpty()?health.end.firstLine:CallHealth.method(health.end)),15,Ui.INK);line(evidence,health.end.src+" → "+health.end.dst,12,Ui.MUTED);line(evidence,"CSeq "+health.end.cseq,11,Ui.MUTED);line(reason,"Reason / Q.850",11,Ui.MUTED);JTextArea value=Ui.note(health.reason);value.setForeground(Ui.INK);value.setRows(2);reason.add(value);}
        ending.add(evidence);ending.add(reason);section(ending);
        JPanel findingsTitle=new JPanel(new BorderLayout());findingsTitle.setOpaque(false);findingsTitle.add(Ui.label("体检结论与证据",18,Ui.INK),BorderLayout.WEST);long attention=health.findings.stream().filter(f->f.state.equals("关注")).count();findingsTitle.add(Ui.label(attention+" 项需关注",12,attention>0?new Color(0xa35f00):Ui.POSITIVE),BorderLayout.EAST);section(findingsTitle);
        JPanel findings=Ui.card(new GridBagLayout());String[] names={"状态","检查项目","观测结果","证据"};double[] weights={.10,.18,.58,.14};
        for(int col=0;col<4;col++){GridBagConstraints c=cell(col,0,weights[col]);findings.add(Ui.label(names[col],12,Ui.MUTED),c);}
        for(int row=0;row<health.findings.size();row++){
            CallHealth.Finding finding=health.findings.get(row);Color color=finding.state.equals("关注")?new Color(0xa35f00):finding.state.equals("正常")?Ui.POSITIVE:Ui.MUTED;
            findings.add(Ui.label(finding.state,12,color),cell(0,row+1,weights[0]));findings.add(Ui.label(finding.title,13,Ui.INK),cell(1,row+1,weights[1]));JTextArea result=Ui.note(finding.detail);result.setRows(2);result.setForeground(Ui.INK);findings.add(result,cell(2,row+1,weights[2]));
            if(finding.evidence!=null){JButton button=Ui.button("查看证据",false);button.setForeground(Ui.ACCENT);button.setName("healthEvidence"+row);button.addActionListener(e->open.accept(finding.evidence));findings.add(button,cell(3,row+1,weights[3]));}else findings.add(Ui.label("—",12,Ui.MUTED),cell(3,row+1,weights[3]));
        }
        section(findings);revalidate();repaint();
    }
    private JPanel metric(String label,String value,String hint){JPanel p=vertical();line(p,label,12,Ui.MUTED);line(p,value,23,Ui.INK);line(p,hint,11,Ui.MUTED);return p;}
    private JPanel moment(String label,long us){String value=CallHealth.time(us);JPanel p=vertical();line(p,label,11,Ui.MUTED);line(p,value.length()>19?value.substring(11,23):value,15,Ui.INK);line(p,value.length()>23?value.substring(0,10)+" · "+value.substring(24):"",11,Ui.MUTED);return p;}
    private GridBagConstraints cell(int column,int row,double weight){GridBagConstraints c=new GridBagConstraints();c.gridx=column;c.gridy=row;c.weightx=weight;c.fill=GridBagConstraints.HORIZONTAL;c.anchor=GridBagConstraints.NORTHWEST;c.insets=new Insets(Ui.u(row==0?4:10),Ui.u(4),Ui.u(6),Ui.u(8));return c;}
    public Dimension getPreferredScrollableViewportSize(){return new Dimension(Ui.u(900),Ui.u(600));}
    public int getScrollableUnitIncrement(Rectangle visible,int orientation,int direction){return Ui.u(24);}
    public int getScrollableBlockIncrement(Rectangle visible,int orientation,int direction){return Math.max(Ui.u(24),visible.height-Ui.u(24));}
    public boolean getScrollableTracksViewportWidth(){return true;}
    public boolean getScrollableTracksViewportHeight(){return false;}
}
