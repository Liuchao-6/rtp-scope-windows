package com.liuchao.rtpscope.desktop;
import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.event.HyperlinkEvent;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.function.*;

/** Call tools share the current capture selection, with all file work off the EDT. */
final class CallToolsPanel extends JPanel {
    private final Supplier<Analysis> analysis;private final Supplier<String> selected;private final Supplier<File> source;
    private final Consumer<Object> open;private final Consumer<String> select;
    private final CallHealthView report;
    private final JLabel state=Ui.label("选择一通电话查看体检",12,Ui.MUTED);
    private final JPanel controls=new JPanel(new FlowLayout(FlowLayout.LEFT));
    private final Map<String,CallRelations> relationsByFile=new HashMap<>();
    private final Supplier<TlsKeyLog> keyLog;private final Supplier<TlsRsaKeys> rsaKeys;private final Consumer<Boolean> busy;
    private CallHealth health;private SwingWorker<?,?> task;
    CallToolsPanel(Supplier<Analysis> a,Supplier<String> s,Supplier<File> f,Consumer<Object> o,Consumer<String> c,Supplier<TlsKeyLog> keys,Supplier<TlsRsaKeys> rsa,Consumer<Boolean> busy){
        super(new BorderLayout(Ui.u(8),Ui.u(8)));analysis=a;selected=s;source=f;open=o;select=c;keyLog=keys;rsaKeys=rsa;this.busy=busy;
        report=new CallHealthView(open);for(String label:new String[]{"刷新体检","导出通话","更多工具"}){JButton b=Ui.button(label,false);controls.add(b);b.addActionListener(e->{if(label.equals("刷新体检"))refresh();else if(label.equals("导出通话"))export();else{JPopupMenu menu=new JPopupMenu();for(String action:new String[]{"通话关联","抓包对照","取消任务"}){JMenuItem item=new JMenuItem(action);item.addActionListener(v->{if(action.equals("通话关联"))links();else if(action.equals("抓包对照"))compare();else if(task!=null)task.cancel(true);});menu.add(item);}menu.show(b,0,b.getHeight());}});}
        add(controls,BorderLayout.NORTH);add(Ui.scroll(report),BorderLayout.CENTER);add(state,BorderLayout.SOUTH);
    }
    void refresh(){
        Analysis a=analysis.get();String id=selected.get();health=a==null||id.isEmpty()?null:CallHealth.inspect(a,id);report.showHealth(health);if(report.getParent() instanceof JViewport)((JViewport)report.getParent()).setViewPosition(new Point(0,0));state.setText(health==null?"选择一通电话查看体检":"当前通话 · "+CallSearch.participants(health.call));
    }
    private boolean ready(){if(analysis.get()==null||selected.get().isEmpty()){state.setText("请先选择一通电话");return false;}return true;}
    void export(){
        if(!ready()||task!=null&&!task.isDone())return;Analysis a=analysis.get();String id=selected.get();
        JCheckBox packets=new JCheckBox("原始关联报文 · PCAPNG",true),audio=new JCheckBox("各方向音频 · WAV",true),html=new JCheckBox("通话体检报告 · HTML",true),maskNumbers=new JCheckBox("报告遮蔽号码",true),maskIps=new JCheckBox("报告遮蔽 IP",true);
        JPanel p=new JPanel(new GridLayout(0,1,6,6));p.add(packets);p.add(audio);p.add(html);p.add(maskNumbers);p.add(maskIps);p.add(new JLabel("遮蔽只影响报告；PCAP 和音频保留原始内容。"));
        if(CallExport.includesSharedConnection(a,id))p.add(new JLabel("TCP / TLS 使用完整关联连接，可能包含同连接的其他通话。"));
        if(JOptionPane.showConfirmDialog(this,p,"导出当前通话",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
        if(!packets.isSelected()&&!audio.isSelected()&&!html.isSelected())return;
        JFileChooser fc=new JFileChooser();fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);if(fc.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;
        File dir=new File(fc.getSelectedFile(),"call-"+System.currentTimeMillis());File input=source.get();
        final boolean exportPackets=packets.isSelected(),exportAudio=audio.isSelected(),exportHtml=html.isSelected(),hideNumbers=maskNumbers.isSelected(),hideIps=maskIps.isSelected();
        task=new SwingWorker<CallExport.Result,Void>(){protected CallExport.Result doInBackground()throws Exception{
            return CallExport.bundle(()->input==null?getClass().getResourceAsStream("/demo-analysis.pcap"):new FileInputStream(input),a,id,dir,exportPackets,exportAudio,exportHtml,hideNumbers,hideIps);
        }protected void done(){busy.accept(false);try{CallExport.Result result=get();state.setText("导出成功 "+result.files.size()+" 项，失败 "+result.failures.size()+" 项 · "+dir.getAbsolutePath());JTextArea text=new JTextArea(result.summary()+"\n保存位置："+dir.getAbsolutePath(),12,60);text.setEditable(false);text.setLineWrap(true);text.setWrapStyleWord(true);JOptionPane.showMessageDialog(CallToolsPanel.this,Ui.scroll(text),result.failures.isEmpty()?"导出完成":"部分项目未能导出",result.failures.isEmpty()?JOptionPane.INFORMATION_MESSAGE:JOptionPane.WARNING_MESSAGE);}catch(Exception e){state.setText(isCancelled()?"导出已取消；已完成的文件保留在 "+dir.getAbsolutePath():"导出未完成："+Ui.error(e));}}};busy.accept(true);state.setText("正在逐项导出…");task.execute();
    }
    void links(){
        if(!ready())return;Analysis a=analysis.get();String id=selected.get();File current=source.get();CallRelations relations=relationsByFile.computeIfAbsent(current==null?"demo:":current.getAbsolutePath(),k->new CallRelations());List<CallRelations.Link> found=relations.find(a,id);DefaultListModel<String> values=new DefaultListModel<>();
        for(CallRelations.Link l:found)values.addElement((l.explicit?"[证据] ":"[候选] ")+l.kind+" · "+(l.first.equals(id)?l.second:l.first)+" · "+l.evidence);
        JList<String> list=new JList<>(values);JPanel p=new JPanel(new BorderLayout(8,8));p.add(new JLabel("字段证据、候选与手动确认分别标记；各通话段保留独立流序。"),BorderLayout.NORTH);p.add(Ui.scroll(list),BorderLayout.CENTER);
        List<Call> candidates=new ArrayList<>();for(Call c:a.calls)if(!c.id.equals(id))candidates.add(c);JComboBox<String> chooser=new JComboBox<>();for(Call c:candidates)chooser.addItem(CallSearch.participants(c)+" · "+c.id);
        JPanel footer=new JPanel(new GridLayout(0,1,5,5));footer.add(chooser);JPanel actions=new JPanel();for(String label:new String[]{"手动确认","移除手动关联","定位所选通话段"}){JButton b=Ui.button(label,false);actions.add(b);b.addActionListener(e->{int n=chooser.getSelectedIndex(),row=list.getSelectedIndex();if(label.equals("手动确认")&&n>=0){relations.confirm(id,candidates.get(n).id);state.setText("已确认通话段关联");}else if(row>=0){CallRelations.Link l=found.get(row);String other=l.first.equals(id)?l.second:l.first;if(label.startsWith("移除")){relations.remove(id,other);values.set(row,"手动关联已移除；字段证据与候选可重新查看");}else select.accept(other);}});}footer.add(actions);p.add(footer,BorderLayout.SOUTH);p.setPreferredSize(new Dimension(Ui.u(760),Ui.u(390)));JOptionPane.showMessageDialog(this,p,"通话关联",JOptionPane.PLAIN_MESSAGE);
    }
    void compare(){
        if(!ready()||task!=null&&!task.isDone())return;JFileChooser fc=new JFileChooser();fc.setDialogTitle("选择另一处抓包");if(fc.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return;
        String offset=JOptionPane.showInputDialog(this,"对照文件时间校正（毫秒，可为负数）","0");if(offset==null)return;final long correction;try{correction=Math.round(Double.parseDouble(offset)*1000);}catch(Exception e){state.setText("校正时间无效");return;}
        File other=fc.getSelectedFile();List<SipMessage> reference=CaptureComparison.messages(analysis.get(),selected.get());
        TlsKeyLog keys=keyLog.get();TlsRsaKeys rsa=rsaKeys.get();task=new SwingWorker<List<CaptureComparison.Match>,Void>(){protected List<CaptureComparison.Match> doInBackground()throws Exception{try(InputStream in=new FileInputStream(other);Analysis a=CaptureEngine.readLarge(in,null,null,keys,rsa)){return CaptureComparison.compare(reference,a.sip,correction);}}
            protected void done(){busy.accept(false);try{List<CaptureComparison.Match> matches=get();JTable table=new JTable(new AbstractTableModel(){String[] names={"观测结果","SIP 消息","基准时间","对照原始时间","校正后差值 ms"};public int getRowCount(){return matches.size();}public int getColumnCount(){return names.length;}public String getColumnName(int n){return names[n];}public Object getValueAt(int r,int c){CaptureComparison.Match m=matches.get(r);return new Object[]{m.state(),m.reference==null?m.other.firstLine:m.reference.firstLine,m.reference==null?"—":Ui.stamp(m.reference.timeUs),m.other==null?"—":Ui.stamp(m.other.timeUs),m.deltaUs==Long.MIN_VALUE?"—":String.format(Locale.ROOT,"%.3f",m.deltaUs/1000.0)}[c];}});JPanel p=new JPanel(new BorderLayout());p.add(new JLabel("校正 "+correction/1000.0+" ms；未见消息需结合抓包范围确认。"),BorderLayout.NORTH);p.add(Ui.scroll(table),BorderLayout.CENTER);p.setPreferredSize(new Dimension(Ui.u(900),Ui.u(480)));JOptionPane.showMessageDialog(CallToolsPanel.this,p,"抓包对照 · "+other.getName(),JOptionPane.PLAIN_MESSAGE);}catch(Exception e){state.setText("对照未完成："+Ui.error(e));}}};busy.accept(true);state.setText("正在读取对照抓包…");task.execute();
    }
    void close(){if(task!=null)task.cancel(true);}
}
