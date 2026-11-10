package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.function.*;
import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;

/** Windows desktop shell. Parsing/decoding/file operations run outside the Swing event thread. */
public final class DesktopApp extends JPanel {
    public static final String VERSION="0.8.7";
    private final UpdateManager updates=new UpdateManager(this);
    public final DesktopModel model=new DesktopModel();
    public final FlowPanel flow=new FlowPanel();
    public final SipDetailPanel detail=new SipDetailPanel();
    public final WaveformPanel waveform=new WaveformPanel();
    private final WavPlayer player=new WavPlayer();
    private final CaptureSession capture=new CaptureSession();
    private final JTextField search=new JTextField();
    private final JTextField callQuick=new JTextField();
    private final JButton tlsKeyButton=Ui.button("解密密钥",false);
    private TlsKeyLog tlsKeys=TlsKeyLog.empty();
    private TlsRsaKeys rsaKeys=TlsRsaKeys.empty();
    private final JButton callAdvanced=Ui.button("筛选",false);
    private final JLabel callMatches=Ui.label("",11,Ui.MUTED);
    private final CaptureWorkspace<File> captureFiles=new CaptureWorkspace<>();
    private final JComboBox<CaptureWorkspace.Entry<File>> fileSelector=new JComboBox<>();
    private final JButton closeFile=Ui.button("关闭文件",false);
    private final JPanel fileDisplay=new JPanel(new CardLayout());
    private final List<JDialog> captureDialogs=new ArrayList<>();
    private final CallToolsPanel callTools=new CallToolsPanel(()->model.analysis,()->model.callId,()->captureFiles.current()==null?null:captureFiles.current().source,this::openEntry,id->{model.callId=id;setCallSearch(model.callSearch);refreshViews();this.tabs.setSelectedIndex(0);},()->this.tlsKeys,()->this.rsaKeys,value->setBusy(value,value?"正在处理通话工具任务…":""));
    private SwingWorker<Analysis,String> importTask;
    private Analysis pendingPrevious;
    private final JButton cancelImport=Ui.button("取消导入",false);
    private final JLabel summary=Ui.label("导入 PCAP / PCAPNG，或先体验演示",12,Ui.MUTED),fileTitle=Ui.label("打开抓包，查看通话",14,Ui.INK),filter=Ui.label("全部通话",13,Ui.ACCENT),status=Ui.label("就绪 · 本地离线分析",11,Ui.MUTED),audioTitle=Ui.label("选择媒体流，还原音频后显示波形",13,Ui.INK),clock=Ui.label("00:00.000 / 00:00.000",12,Ui.MUTED),keySummary=Ui.label("生成波形后显示按键信息",12,Ui.POSITIVE);
    private final JButton importButton=Ui.button("导入抓包",true),demoButton=Ui.button("体验演示",false),captureButton=Ui.button("本机抓包",false),playSelected=Ui.button("播放选中",true),toggle=Ui.button("播放 / 暂停",false),export=Ui.button("导出 WAV",false),warnings=Ui.button("分析提示",false);
    private final JSlider seek=new JSlider(0,10000,0);
    private final JPanel playerBody=new JPanel(new BorderLayout(Ui.u(10),Ui.u(6)));
    private final JButton playerVisibility=Ui.button("展开播放器",false),compactToggle=Ui.button("播放",false);
    private final JLabel compactClock=Ui.label("",12,Ui.MUTED);
    private List<Call> calls=Collections.emptyList();
    private final JList<Call> callList=new JList<>();
    private final JTabbedPane tabs=new JTabbedPane(),detailTabs=new JTabbedPane();
    private JSplitPane rightSplit;private JPanel detailRegion;
    private final JTable sipTable=new JTable(),rtpTable=new JTable(),eventTable=new JTable(),issueTable=new JTable();
    private final javax.swing.Timer searchTimer,ticker;
    private List<SipMessage> messages=new ArrayList<>();
    private List<RtpStream> streams=new ArrayList<>(),audioStreams=new ArrayList<>();
    private List<DtmfParser.Event> events=new ArrayList<>();
    private List<QualityAnalyzer.Issue> issues=new ArrayList<>();
    private RtpStream inspectedStream;
    private File currentWav,captureFile,captureLog;
    private String fileName="";
    private boolean busy,closed,updatingSeek,updatingCalls,updatingFiles,playerExpanded;
    private long pendingSeek;
    private Consumer<AudioPreview> transcriptHandler;
    private File routedWav;private boolean[] audible;private boolean stereoPlayback;private float playbackSpeed=1;private long loopA=-1,loopB=-1;
    public void setTranscriptHandler(Consumer<AudioPreview> handler){transcriptHandler=handler;}
    void preparingTranscript(boolean value){setBusy(value,value?"正在准备转写音频…":"");}

    public DesktopApp() {
        super(new BorderLayout(Ui.u(10),Ui.u(10)));NativeMedia.install();setBackground(Ui.BG);setBorder(BorderFactory.createEmptyBorder(Ui.u(14),Ui.u(14),Ui.u(10),Ui.u(14)));
        JPanel top=new JPanel(new BorderLayout(Ui.u(12),Ui.u(9)));top.setBackground(Ui.BG);
        JPanel brand=new JPanel(new BorderLayout());brand.setBackground(Ui.BG);JLabel logo=Ui.label("超哥话探",22,Ui.INK);logo.setIcon(new ImageIcon(Ui.icon().getScaledInstance(Ui.u(30),Ui.u(30),Image.SCALE_SMOOTH)));logo.setIconTextGap(Ui.u(10));brand.add(logo,BorderLayout.WEST);
        JPanel release=new JPanel(new FlowLayout(FlowLayout.RIGHT,Ui.u(10),0));release.setOpaque(false);release.add(Ui.label("SIP · RTP 通话分析  |  Windows "+VERSION,12,Ui.MUTED));JButton checkUpdates=Ui.button("检查更新",false);checkUpdates.setName("checkUpdates");checkUpdates.setToolTipText("查询 GitHub 正式版；文件分析仍在本机完成");checkUpdates.addActionListener(e->updates.check(true));release.add(checkUpdates);brand.add(release,BorderLayout.EAST);top.add(brand,BorderLayout.NORTH);
        JPanel tools=new JPanel(new BorderLayout(Ui.u(12),0));tools.setBackground(Ui.BG);
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT,Ui.u(7),0));actions.setOpaque(false);actions.add(importButton);
        tlsKeyButton.setName("importTlsKeys");tlsKeyButton.setToolTipText("分别导入 RSA 私钥或 TLS key log，可在导入抓包前后加载");tlsKeyButton.addActionListener(e->chooseTlsKeys());actions.add(tlsKeyButton);
        JButton callMenu=Ui.button("通话工具",false),more=Ui.button("更多",false);actions.add(callMenu);actions.add(more);actions.add(cancelImport);cancelImport.setVisible(false);cancelImport.addActionListener(e->{if(importTask!=null)importTask.cancel(true);});
        callMenu.addActionListener(e->{JPopupMenu menu=new JPopupMenu();for(String label:new String[]{"通话体检","导出当前通话","通话关联","抓包对照"}){JMenuItem item=new JMenuItem(label);item.setEnabled(!busy);item.addActionListener(v->{if(label.equals("通话体检"))tabs.setSelectedIndex(4);else if(label.startsWith("导出"))callTools.export();else if(label.equals("通话关联"))callTools.links();else callTools.compare();});menu.add(item);}menu.show(callMenu,0,callMenu.getHeight());});
        more.addActionListener(e->{JPopupMenu menu=new JPopupMenu();for(String label:new String[]{"体验演示","启动 / 停止抓包","分析提示","关于"}){JMenuItem item=new JMenuItem(label);item.addActionListener(v->{if(label.equals("体验演示"))demoButton.doClick();else if(label.startsWith("启动"))captureButton.doClick();else if(label.equals("分析提示"))showWarnings();else about();});menu.add(item);}menu.addSeparator();JMenuItem check=new JMenuItem("检查更新");check.addActionListener(v->updates.check(true));menu.add(check);JCheckBoxMenuItem automatic=new JCheckBoxMenuItem("启动时检查更新",updates.automatic());automatic.addActionListener(v->updates.automatic(automatic.isSelected()));menu.add(automatic);menu.show(more,0,more.getHeight());});
        search.setPreferredSize(new Dimension(Ui.u(260),Ui.u(35)));search.putClientProperty("JTextField.placeholderText","搜索当前通话的报文、编码或按键");search.setToolTipText("左侧找通话；这里筛选 IP、端口、SIP 方法、正文、编码或按键");JPanel searchArea=new JPanel(new BorderLayout(Ui.u(5),0));searchArea.setOpaque(false);searchArea.add(search,BorderLayout.CENTER);JButton clear=Ui.button("清空",false);searchArea.add(clear,BorderLayout.EAST);JButton about=Ui.button("关于",false);tools.add(actions,BorderLayout.CENTER);tools.add(searchArea,BorderLayout.EAST);
        JPanel fileInfo=new JPanel(new BorderLayout(Ui.u(14),0));fileInfo.setBackground(Ui.BG);fileDisplay.setOpaque(false);fileDisplay.add(fileTitle,"empty");
        JPanel fileControls=new JPanel(new BorderLayout(Ui.u(7),0));fileControls.setOpaque(false);fileSelector.setName("captureFiles");fileSelector.setMinimumSize(new Dimension(Ui.u(160),Ui.u(32)));fileSelector.setToolTipText("切换抓包文件，各文件独立分析；再次导入可追加文件");fileSelector.getAccessibleContext().setAccessibleName("切换抓包文件");
        fileSelector.setRenderer(new DefaultListCellRenderer(){public Component getListCellRendererComponent(JList<?> list,Object value,int index,boolean selected,boolean focus){JLabel label=(JLabel)super.getListCellRendererComponent(list,value,index,selected,focus);int n=index<0?captureFiles.activeIndex():index;if(value!=null&&n>=0&&n<captureFiles.size()){label.setText(captureFiles.label(n));label.setToolTipText(captureFiles.get(n).id);}return label;}});
        fileControls.add(fileSelector,BorderLayout.CENTER);closeFile.setName("closeCapture");closeFile.setToolTipText("从列表移除当前文件，保留原始抓包");fileControls.add(closeFile,BorderLayout.EAST);fileDisplay.add(fileControls,"files");fileInfo.add(fileDisplay,BorderLayout.CENTER);fileInfo.add(summary,BorderLayout.EAST);
        fileSelector.addActionListener(e->{if(!updatingFiles&&!busy&&fileSelector.getSelectedIndex()>=0&&(fileSelector.getSelectedIndex()!=captureFiles.activeIndex()||model.analysis==null))selectCapture(fileSelector.getSelectedIndex());});closeFile.addActionListener(e->closeCapture());
        JPanel info=new JPanel(new BorderLayout(Ui.u(12),Ui.u(12)));info.setBackground(Ui.BG);info.add(tools,BorderLayout.NORTH);info.add(fileInfo,BorderLayout.SOUTH);top.add(info,BorderLayout.CENTER);add(top,BorderLayout.NORTH);
        importButton.addActionListener(e->chooseFile());demoButton.addActionListener(e->load(null));captureButton.addActionListener(e->captureAction());clear.addActionListener(e->search.setText(""));warnings.addActionListener(e->showWarnings());about.addActionListener(e->about());
        searchTimer=new javax.swing.Timer(200,e->{model.query=search.getText();refreshViews();});searchTimer.setRepeats(false);search.getDocument().addDocumentListener(new DocumentListener(){public void insertUpdate(DocumentEvent e){searchTimer.restart();}public void removeUpdate(DocumentEvent e){searchTimer.restart();}public void changedUpdate(DocumentEvent e){searchTimer.restart();}});
        JPanel left=new JPanel(new BorderLayout(0,Ui.u(8)));left.setPreferredSize(new Dimension(Ui.u(235),Ui.u(400)));left.setMinimumSize(new Dimension(Ui.u(170),Ui.u(100)));left.setBorder(BorderFactory.createEmptyBorder(Ui.u(10),Ui.u(10),Ui.u(10),Ui.u(10)));
        JPanel callTop=new JPanel(new BorderLayout(0,Ui.u(6)));JPanel callHeading=new JPanel(new BorderLayout());callHeading.add(Ui.label("通话",17,Ui.INK),BorderLayout.WEST);JPanel callButtons=new JPanel(new FlowLayout(FlowLayout.RIGHT,Ui.u(3),0));JButton all=Ui.button("全部",false);callAdvanced.setName("callAdvanced");callButtons.add(callAdvanced);callButtons.add(all);callHeading.add(callButtons,BorderLayout.EAST);callTop.add(callHeading,BorderLayout.NORTH);
        callQuick.setName("callQuickSearch");callQuick.putClientProperty("JTextField.placeholderText","找通话：号码、IP、Call-ID");callQuick.setToolTipText("搜索本文件所有通话；组合主被叫和时间条件请点筛选");callQuick.setPreferredSize(new Dimension(Ui.u(180),Ui.u(34)));callTop.add(callQuick,BorderLayout.CENTER);callTop.add(callMatches,BorderLayout.SOUTH);left.add(callTop,BorderLayout.NORTH);
        callList.setName("calls");callList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);callList.setFixedCellHeight(Ui.u(122));callList.setFixedCellWidth(Ui.u(180));callList.setCellRenderer(new CallRenderer());
        callList.addComponentListener(new ComponentAdapter(){public void componentResized(ComponentEvent e){int width=callList.getWidth();if(width>0&&width!=callList.getFixedCellWidth())callList.setFixedCellWidth(width);}});
        left.add(Ui.scroll(callList),BorderLayout.CENTER);left.add(Ui.note("先按号码、时间、IP 找通话\n选择结果后查看完整流序\n上方搜索用于筛选报文"),BorderLayout.SOUTH);
        callAdvanced.addActionListener(e->showCallSearch());
        callQuick.getDocument().addDocumentListener(new DocumentListener(){private void changed(){if(updatingCalls)return;model.callSearch.keyword=callQuick.getText();refreshCalls();}public void insertUpdate(DocumentEvent e){changed();}public void removeUpdate(DocumentEvent e){changed();}public void changedUpdate(DocumentEvent e){changed();}});
        all.addActionListener(e->{model.callId="";setCallSearch(new CallSearch.Filter());filter.setText("全部通话");refreshViews();});
        callList.addListSelectionListener(e->{if(!updatingCalls&&!e.getValueIsAdjusting()){Call c=callList.getSelectedValue();model.callId=c==null?"":c.id;if(c!=null){searchTimer.stop();search.setText("");searchTimer.stop();model.query="";}filter.setText(c==null?"全部通话":"当前通话："+CallSearch.participants(c)+" · "+c.id);refreshViews();}});
        JPanel timeline=new JPanel(new BorderLayout(0,Ui.u(8)));JPanel timelineTools=new JPanel(new BorderLayout());timelineTools.setBorder(BorderFactory.createEmptyBorder(Ui.u(8),Ui.u(10),0,Ui.u(8)));timelineTools.add(Ui.label("按时间查看交互，点击消息查看详情",12,Ui.MUTED),BorderLayout.CENTER);JButton expand=Ui.button("放大流序图",false);timelineTools.add(expand,BorderLayout.EAST);timeline.add(timelineTools,BorderLayout.NORTH);timeline.add(flow.scrollPane(),BorderLayout.CENTER);expand.addActionListener(e->expandFlow());flow.setOpenListener(this::openEntry);
        tabs.setName("analysisTabs");tabs.addTab("流序图",timeline);tabs.addTab("SIP 报文",Ui.scroll(sipTable));tabs.addTab("RTP 媒体",mediaTab());tabs.addTab("DTMF 按键",Ui.scroll(eventTable));tabs.addTab("通话体检",callTools);tabs.addChangeListener(e->{if(tabs.getSelectedIndex()==4)callTools.refresh();if(rightSplit!=null)showDetails(tabs.getSelectedIndex()!=4);});
        JPanel center=new JPanel(new BorderLayout(0,Ui.u(7)));center.setBackground(Ui.BG);center.setMinimumSize(new Dimension(Ui.u(280),Ui.u(150)));center.add(filter,BorderLayout.NORTH);center.add(tabs,BorderLayout.CENTER);
        detail.setStatusListener(this::status);detailTabs.addTab("报文 / 摘要",detail);JPanel quality=new JPanel(new BorderLayout(0,Ui.u(7)));quality.add(Ui.note("双击问题时间点定位音频。\n缺包是抓包侧证据；到达延迟表示卡顿风险。"),BorderLayout.NORTH);quality.add(Ui.scroll(issueTable),BorderLayout.CENTER);detailTabs.addTab("质量时间点",quality);detailTabs.setMinimumSize(new Dimension(Ui.u(260),Ui.u(150)));
        detailRegion=new JPanel(new BorderLayout());JPanel detailHeading=new JPanel(new FlowLayout(FlowLayout.LEFT,Ui.u(4),0));detailHeading.setOpaque(false);detailHeading.add(Ui.label("报文 / 摘要",12,Ui.INK));JButton closeDetail=Ui.button("×",false);closeDetail.setName("hideDetails");closeDetail.setToolTipText("收起详情，给流序图或概览留出空间");closeDetail.setMargin(new Insets(0,Ui.u(5),0,Ui.u(5)));closeDetail.setPreferredSize(new Dimension(Ui.u(24),Ui.u(24)));closeDetail.addActionListener(e->showDetails(false));detailHeading.add(closeDetail);detailTabs.setTabComponentAt(0,detailHeading);detailRegion.add(detailTabs,BorderLayout.CENTER);
        rightSplit=new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,center,detailRegion);rightSplit.setResizeWeight(0.67);rightSplit.setDividerLocation(Ui.u(710));rightSplit.setBorder(null);
        JSplitPane body=new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,left,rightSplit);body.setDividerLocation(Ui.u(235));body.setResizeWeight(0);body.setBorder(null);add(body,BorderLayout.CENTER);
        JPanel bottom=new JPanel(new BorderLayout(Ui.u(10),Ui.u(6)));bottom.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Ui.LINE),BorderFactory.createEmptyBorder(Ui.u(10),Ui.u(12),Ui.u(7),Ui.u(12))));JPanel audioHeading=new JPanel(new BorderLayout(Ui.u(12),0));audioHeading.add(audioTitle,BorderLayout.CENTER);JPanel compactBar=new JPanel(new FlowLayout(FlowLayout.RIGHT,Ui.u(8),0));compactBar.add(keySummary);compactBar.add(compactClock);compactBar.add(compactToggle);compactBar.add(playerVisibility);audioHeading.add(compactBar,BorderLayout.EAST);bottom.add(audioHeading,BorderLayout.NORTH);
        playerVisibility.setName("playerVisibility");compactToggle.setName("compactPlayback");playerVisibility.setToolTipText("收起波形和播放控件，声音继续播放");playerVisibility.addActionListener(e->setPlayerExpanded(!playerExpanded));compactToggle.addActionListener(e->togglePlayback());
        JScrollPane waveScroll=new JScrollPane(waveform,JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,JScrollPane.HORIZONTAL_SCROLLBAR_NEVER){public Dimension getPreferredSize(){Dimension size=super.getPreferredSize();int limit=DesktopApp.this.getHeight()>0&&DesktopApp.this.getHeight()<Ui.u(820)?140:232;size.height=Math.min(Ui.u(limit),size.height);return size;}};waveScroll.setBorder(null);waveScroll.getVerticalScrollBar().setUnitIncrement(Ui.u(32));JScrollBar wavePan=new JScrollBar(JScrollBar.HORIZONTAL);wavePan.setVisible(false);JPanel waveArea=new JPanel(new BorderLayout());waveArea.add(waveScroll,BorderLayout.CENTER);waveArea.add(wavePan,BorderLayout.SOUTH);playerBody.add(waveArea,BorderLayout.CENTER);
        JPanel controls=new JPanel(new BorderLayout(Ui.u(10),Ui.u(5)));JPanel progress=new JPanel(new BorderLayout(Ui.u(10),0));progress.add(seek,BorderLayout.CENTER);progress.add(clock,BorderLayout.EAST);controls.add(progress,BorderLayout.NORTH);
        JPanel buttons=new JPanel(new FlowLayout(FlowLayout.LEFT,Ui.u(7),0));buttons.add(playSelected);buttons.add(toggle);buttons.add(export);buttons.add(Ui.label("音量",11,Ui.MUTED));JSlider volume=new JSlider(0,100,80);volume.setPreferredSize(new Dimension(Ui.u(100),Ui.u(26)));buttons.add(volume);JButton keys=Ui.button("按键列表",false);keys.addActionListener(e->showWaveformKeys());buttons.add(keys);JButton zoomOut=Ui.button("−",false),zoomIn=Ui.button("＋",false),fit=Ui.button("全览",false);JLabel zoomLabel=Ui.label("1×",11,Ui.MUTED);buttons.add(zoomOut);buttons.add(zoomIn);buttons.add(fit);buttons.add(zoomLabel);
        JButton listening=Ui.button("试听设置",false);listening.setName("listeningOptions");buttons.add(listening);listening.addActionListener(e->showListeningOptions());
        waveform.setToolTipText("Ctrl＋滚轮缩放，Shift＋滚轮平移；红：缺包，黄：延迟，紫：时间戳衔接，绿：按键");
        final boolean[] updatingPan={false};Runnable zoomState=()->{WaveformViewport v=waveform.viewport();zoomLabel.setText(String.format(Locale.ROOT,"%.1f×",v.zoom()));boolean ready=waveform.preview()!=null;zoomOut.setEnabled(ready&&v.zoom()>1);zoomIn.setEnabled(ready&&v.zoom()<64);fit.setEnabled(ready);updatingPan[0]=true;int extent=Math.max(1,(int)Math.round(100000/v.zoom()));wavePan.setValues((int)Math.round(v.startMs()/v.durationMs()*100000),extent,0,100000);wavePan.setBlockIncrement(extent);wavePan.setUnitIncrement(Math.max(1,extent/10));wavePan.setVisible(ready&&v.zoom()>1);updatingPan[0]=false;};waveform.setWindowListener(zoomState);zoomState.run();
        zoomOut.addActionListener(e->waveform.zoomBy(0.5));zoomIn.addActionListener(e->waveform.zoomBy(2));fit.addActionListener(e->waveform.fit());wavePan.addAdjustmentListener(e->{if(!updatingPan[0])waveform.panTo(wavePan.getValue()/100000.0*waveform.viewport().durationMs());});controls.add(buttons,BorderLayout.CENTER);playerBody.add(controls,BorderLayout.SOUTH);bottom.add(playerBody,BorderLayout.CENTER);bottom.add(status,BorderLayout.SOUTH);add(bottom,BorderLayout.SOUTH);setPlayerExpanded(false);
        volume.addChangeListener(e->player.setVolume(volume.getValue()/100f));waveform.setSeekListener(ms->seekTo((long)ms));waveform.setKeyListener(this::openWaveformKey);seek.addChangeListener(e->{if(!updatingSeek&&!seek.getValueIsAdjusting())seekTo((long)(duration()*seek.getValue()/10000.0));});
        playSelected.addActionListener(e->{try{List<RtpStream> selected=model.playbackSelection();if(selected.isEmpty())status("请在 RTP 列表勾选媒体流，或双击某一流播放");else renderAudio(selected,true,null);}catch(IllegalArgumentException ex){error(ex);}});toggle.addActionListener(e->togglePlayback());export.addActionListener(e->exportWav());
        setupTables();installDrop();ticker=new javax.swing.Timer(120,e->tick());ticker.start();refreshViews();
    }
    public boolean isPlayerExpanded(){return playerExpanded;}
    public void setPlayerExpanded(boolean expanded){
        playerExpanded=expanded;playerBody.setVisible(expanded);playerVisibility.setText(expanded?"收起播放器":"展开播放器");playerVisibility.getAccessibleContext().setAccessibleDescription(expanded?"收起 RTP 波形和播放器，播放继续":"展开 RTP 波形和播放器");updateCompactPlayer();revalidate();repaint();
    }
    private void updateCompactPlayer(){
        keySummary.setVisible(playerExpanded);compactClock.setVisible(!playerExpanded&&currentWav!=null);compactToggle.setVisible(!playerExpanded&&currentWav!=null);compactToggle.setEnabled(!busy&&currentWav!=null);
        compactClock.setText(clock.getText());compactToggle.setText(player.playing()?"暂停":"播放");
    }
    private JPanel mediaTab() {
        JPanel pane=new JPanel(new BorderLayout(0,Ui.u(7)));JPanel buttons=new JPanel(new FlowLayout(FlowLayout.LEFT,Ui.u(6),0));JButton play=Ui.button("播放此流",true),graph=Ui.button("波形 / 质量",false),duplex=Ui.button("播放当前通话双向",false);buttons.add(play);buttons.add(graph);buttons.add(duplex);JButton text=Ui.button("转写当前通话",false);buttons.add(text);text.addActionListener(e->{if(model.callId.isEmpty()){status("请先选择一通电话");return;}List<RtpStream> audio=new ArrayList<>();for(RtpStream stream:model.analysis.streams)if(stream.callId.equals(model.callId)&&stream.playable())audio.add(stream);renderAudio(audio,false,()->{if(transcriptHandler!=null)transcriptHandler.accept(waveform.preview());});});pane.add(buttons,BorderLayout.NORTH);pane.add(Ui.scroll(rtpTable),BorderLayout.CENTER);
        play.addActionListener(e->{RtpStream s=selectedStream();if(s!=null)renderAudio(Collections.singletonList(s),true,null);});graph.addActionListener(e->{RtpStream s=selectedStream();if(s!=null){if(s.playable())renderAudio(Collections.singletonList(s),false,null);else showQuality(s);}});
        duplex.addActionListener(e->{if(model.callId.isEmpty()){status("请先在左侧选择一个通话");return;}List<RtpStream> supported=new ArrayList<>();if(model.analysis!=null)for(RtpStream s:model.analysis.streams)if(s.callId.equals(model.callId)&&s.playable())supported.add(s);renderAudio(supported,true,null);});return pane;
    }
    private void setupTables() {
        for(JTable table:new JTable[]{sipTable,rtpTable,eventTable,issueTable}){table.setRowHeight(Ui.u(36));table.setShowGrid(false);table.setIntercellSpacing(new Dimension(Ui.u(10),0));table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);table.setAutoCreateRowSorter(true);table.setFillsViewportHeight(true);table.getTableHeader().setReorderingAllowed(false);}
        sipTable.getSelectionModel().addListSelectionListener(e->{if(!e.getValueIsAdjusting()){int index=index(sipTable);if(index>=0&&index<messages.size()){showDetails(true);detail.showSip(messages.get(index));detailTabs.setSelectedIndex(0);}}});
        rtpTable.getSelectionModel().addListSelectionListener(e->{if(!e.getValueIsAdjusting()){RtpStream s=selectedStream();if(s!=null)showQuality(s);}});
        rtpTable.addMouseListener(new MouseAdapter(){public void mouseClicked(MouseEvent e){if(e.getClickCount()==2){RtpStream s=selectedStream();if(s!=null&&s.playable())renderAudio(Collections.singletonList(s),true,null);}}});
        eventTable.getSelectionModel().addListSelectionListener(e->{if(!e.getValueIsAdjusting()){int n=index(eventTable);if(n>=0&&n<events.size())showEvent(events.get(n));}});
        issueTable.addMouseListener(new MouseAdapter(){public void mouseClicked(MouseEvent e){if(e.getClickCount()==2)locateIssue();}});
        issueTable.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,0),"locate");issueTable.getActionMap().put("locate",new AbstractAction(){public void actionPerformed(ActionEvent e){locateIssue();}});
        sipTable.setDefaultRenderer(Object.class,new DefaultTableCellRenderer(){public Component getTableCellRendererComponent(JTable t,Object v,boolean selected,boolean focus,int r,int c){Component comp=super.getTableCellRendererComponent(t,v,selected,focus,r,c);if(!selected){int index=t.convertRowIndexToModel(r);Color color=Ui.INK;if(index<messages.size()){String first=messages.get(index).firstLine;color=Ui.syntaxColor(first.startsWith("SIP/2.0 1")?SipSyntax.Kind.PROVISIONAL:first.startsWith("SIP/2.0 2")?SipSyntax.Kind.SUCCESS:first.startsWith("SIP/2.0")?SipSyntax.Kind.ERROR:SipSyntax.Kind.METHOD);}comp.setForeground(color);}return comp;}});
    }
    private static int index(JTable table){return table.getSelectedRow()<0?-1:table.convertRowIndexToModel(table.getSelectedRow());}
    private RtpStream selectedStream(){int n=index(rtpTable);return n>=0&&n<streams.size()?streams.get(n):null;}
    public void acceptAnalysis(Analysis analysis,String name) {
        if(model.analysis!=null&&model.analysis!=analysis)try{model.analysis.close();}catch(IOException ignored){}
        model.load(analysis);setPlayerExpanded(false);fileName=name;searchTimer.stop();search.setText("");setCallSearch(new CallSearch.Filter());
        filter.setText("全部通话");fileTitle.setText(name);fileTitle.setToolTipText(name);summary.setText(String.format(Locale.ROOT,"%,d 包   ·   %d 通话   ·   %d SIP   ·   %d RTP   ·   %d 次按键",analysis.packets,analysis.calls.size(),analysis.sip.size(),analysis.streams.size(),analysis.events.size())+(analysis.partial?" · 不完整文件":""));
        detail.showText(analysis.partial?"已恢复导入":"分析完成",name,(analysis.partial?"文件不完整或局部损坏，已保留可解析的包。点击「分析提示」查看恢复范围。\n\n":"")+"左侧选择通话，或在流序图中点击消息。\n\nSIP 详情支持字段着色和复制原文。\nRTP 流可播放、生成波形、分析缺包和到达延迟。\n识别 RFC 2833 / 4733、SIP INFO 和 In-band DTMF，按类型显示。");refreshViews();status((analysis.partial?"已恢复导入 · 已分析 "+analysis.packets+" 包":"已导入")+" · "+analysis.warnings.size()+" 项分析提示");
    }
    public void refreshViews() {
        if(tabs.getSelectedIndex()==4)callTools.refresh();flow.setData(model.flow());messages=model.messages();streams=model.streams();events=model.events();
        sipTable.setModel(new AbstractTableModel(){String[] names={"时间","请求 / 响应","源 IP:端口","目的 IP:端口","CSeq","传输"};public int getRowCount(){return messages.size();}public int getColumnCount(){return names.length;}public String getColumnName(int c){return names[c];}public Object getValueAt(int r,int c){SipMessage m=messages.get(r);return new Object[]{Ui.stamp(m.timeUs),m.firstLine,m.src,m.dst,m.cseq,m.transport}[c];}});
        rtpTable.setModel(new AbstractTableModel(){String[] names={"选中","编码","源 IP:端口","目的 IP:端口","PT","SSRC","包数","缺包","延迟突增"};public int getRowCount(){return streams.size();}public int getColumnCount(){return names.length;}public String getColumnName(int c){return names[c];}public Class<?> getColumnClass(int c){return c==0?Boolean.class:c>=4&&c!=5?Long.class:String.class;}public boolean isCellEditable(int r,int c){return c==0&&streams.get(r).playable();}public void setValueAt(Object v,int r,int c){if(Boolean.TRUE.equals(v))model.selected.add(streams.get(r));else model.selected.remove(streams.get(r));fireTableCellUpdated(r,c);}public Object getValueAt(int r,int c){RtpStream s=streams.get(r);return new Object[]{model.selected.contains(s),s.encrypted?"SRTP / "+s.codec:s.codec,s.src,s.dst,(long)s.pt,String.format(Locale.ROOT,"%08X",s.ssrc),(long)s.packets.size(),s.lost,s.quality==null?0L:s.quality.delaySpikes()}[c];}});
        eventTable.setModel(new AbstractTableModel(){String[] names={"按键","类型","首包时间","持续时间","源 IP:端口","目的 IP:端口","状态"};public int getRowCount(){return events.size();}public int getColumnCount(){return names.length;}public String getColumnName(int c){return names[c];}public Object getValueAt(int r,int c){DtmfParser.Event e=events.get(r);return new Object[]{e.key,e.typeLabel(),Ui.stamp(e.firstSeenUs),e.durationText(),e.src,e.dst,e.stateText()}[c];}});
        sipTable.getColumnModel().getColumn(1).setPreferredWidth(Ui.u(240));rtpTable.getColumnModel().getColumn(0).setMaxWidth(Ui.u(48));
        tabs.setTitleAt(0,"流序图 "+flow.data().entries.size());tabs.setTitleAt(1,"SIP "+messages.size());tabs.setTitleAt(2,"RTP "+streams.size());tabs.setTitleAt(3,"按键 "+events.size());warnings.setEnabled(model.analysis!=null&&!model.analysis.warnings.isEmpty());if(tabs.getSelectedIndex()==4)callTools.refresh();updateButtons();
    }
    public void setSearch(String query){searchTimer.stop();search.setText(query);searchTimer.stop();model.query=query;refreshViews();}
    public void setCallSearch(CallSearch.Filter value){CallSearch.find(Collections.emptyList(),value);model.callSearch=value.copy();updatingCalls=true;callQuick.setText(value.keyword);updatingCalls=false;refreshCalls();}
    private void replaceCalls(List<Call> values){
        final List<Call> snapshot=Collections.unmodifiableList(new ArrayList<>(values));calls=snapshot;
        // Replace once: per-row additions make FlatLaf repeatedly measure the entire list.
        callList.setModel(new AbstractListModel<Call>(){public int getSize(){return snapshot.size();}public Call getElementAt(int index){return snapshot.get(index);}});
    }
    private void refreshCalls(){
        boolean previous=updatingCalls;updatingCalls=true;
        try{replaceCalls(model.calls());for(int n=0;n<calls.size();n++)if(calls.get(n).id.equals(model.callId)){callList.setSelectedIndex(n);break;}}
        finally{updatingCalls=previous;}
        callMatches.setText("匹配 "+calls.size()+" / "+(model.analysis==null?0:model.analysis.calls.size())+" 通话"+(model.callSearch.empty()?"":" · 筛选中"));
    }
    private void showCallSearch(){if(busy)return;CallFilterPanel pane=new CallFilterPanel(model.callSearch);for(;;){int result=JOptionPane.showConfirmDialog(this,pane,"筛选通话",JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE);if(result!=JOptionPane.OK_OPTION)return;try{setCallSearch(pane.value());return;}catch(IllegalArgumentException e){JOptionPane.showMessageDialog(this,e.getMessage(),"筛选条件",JOptionPane.WARNING_MESSAGE);}}}
    public boolean isBusy(){return busy;}
    public File renderedFile(){return currentWav;}
    public int callCount(){return calls.size();}
    public String waveformKeySummary(){return keySummary.getText();}
    public void previewAudio(List<RtpStream> streams){renderAudio(streams,false,null);}
    private void showDetails(boolean visible){
        if(detailRegion==null)return;boolean changed=detailRegion.isVisible()!=visible;detailRegion.setVisible(visible);rightSplit.setDividerSize(visible?Ui.u(10):0);if(visible&&changed)rightSplit.setDividerLocation(.64);rightSplit.revalidate();
    }
    public void openEntry(Object source) {
        showDetails(true);
        if(source instanceof SipMessage){detail.showSip((SipMessage)source);detailTabs.setSelectedIndex(0);}
        else if(source instanceof CallHealth.KeySummary){CallHealth.KeySummary keys=(CallHealth.KeySummary)source;detail.showText("按键汇总","Call-ID："+keys.callId,keys.detailText());detailTabs.setSelectedIndex(0);}
        else if(source instanceof DtmfParser.Event)showEvent((DtmfParser.Event)source);
        else if(source instanceof RtpStream){RtpStream s=(RtpStream)source;showQuality(s);if(s.playable())renderAudio(Collections.singletonList(s),false,null);}
    }
    private void openWaveformKey(AudioPreview.Key key) {
        seekTo((long)key.startMs);
        if(key.event!=null)showEvent(key.event);
        else {detail.showText("按键 "+key.value,"波形 "+(key.track+1),String.format(Locale.ROOT,"音频位置：%s\n持续时长：%.1f ms",Ui.clock((long)key.startMs),key.durationMs));detailTabs.setSelectedIndex(0);}
        status(key.badgeText()+" · "+Ui.clock((long)key.startMs)+" · "+(key.event==null?String.format(Locale.ROOT,"%.1f ms",key.durationMs):key.event.durationText()));
    }
    private void showWaveformKeys() {
        AudioPreview preview=waveform.preview();if(preview==null||preview.keys.isEmpty()){status("当前音频没有可显示的按键");return;}
        JDialog dialog=new JDialog((Frame)SwingUtilities.getWindowAncestor(this),"音频按键",false);trackCaptureDialog(dialog);
        JTable table=new JTable(new AbstractTableModel(){String[] names={"按键","类型","音频位置","持续时间","波形","方向"};public int getRowCount(){return preview.keys.size();}public int getColumnCount(){return names.length;}public String getColumnName(int c){return names[c];}public Object getValueAt(int r,int c){AudioPreview.Key key=preview.keys.get(r);return new Object[]{key.value,key.typeLabel(),Ui.clock((long)key.startMs),key.event==null?key.durationMs+" ms":key.event.durationText(),key.track+1,preview.tracks.get(key.track).label}[c];}});
        table.setRowHeight(Ui.u(36));table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);table.getColumnModel().getColumn(5).setPreferredWidth(Ui.u(330));
        Runnable locate=()->{int n=table.getSelectedRow();if(n>=0)openWaveformKey(preview.keys.get(n));};
        table.addMouseListener(new MouseAdapter(){public void mouseClicked(MouseEvent e){if(e.getClickCount()==2)locate.run();}});table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,0),"locate");table.getActionMap().put("locate",new AbstractAction(){public void actionPerformed(ActionEvent e){locate.run();}});
        JPanel content=new JPanel(new BorderLayout(0,Ui.u(10)));content.setBorder(BorderFactory.createEmptyBorder(Ui.u(14),Ui.u(14),Ui.u(14),Ui.u(14)));content.add(Ui.label(preview.keySummary()+"  ·  双击或回车定位并查看详情",13,Ui.MUTED),BorderLayout.NORTH);content.add(Ui.scroll(table),BorderLayout.CENTER);dialog.setContentPane(content);Ui.fitWindow(dialog,850,420,600,300);dialog.setLocationRelativeTo(this);dialog.setVisible(true);
    }
    private void showEvent(DtmfParser.Event e){showDetails(true);detailTabs.setSelectedIndex(0);detail.showText("按键 "+e.key+" · "+e.typeLabel(),e.src+" → "+e.dst+"\nCall-ID："+e.callId,"首包："+Ui.stamp(e.firstSeenUs)+"\n末包："+Ui.stamp(e.lastSeenUs)+"\n"+e.detailText());}
    private void showQuality(RtpStream s) {
        inspectedStream=s;QualityAnalyzer.Report q=s.quality;StringBuilder text=new StringBuilder("编码："+s.codec+"\nPT："+s.pt+"\nSSRC："+String.format(Locale.ROOT,"%08X",s.ssrc)+"\n包数："+s.packets.size()+"\n");
        if(q!=null)text.append(String.format(Locale.ROOT,"\n同方向 / 同 SSRC，全部 PT %s\n唯一 %d，缺少 %d（%.2f%%）\n重复 %d，乱序 %d，序号跳变 %d\n到达延迟突增 %d 次（阈值 80 ms）\n最大抖动 %.2f ms\n最大到包间隔 %.2f ms\n可靠抓包时间：%s\n",q.payloadTypes,q.unique,q.lost,q.lossPercent(),q.duplicates,q.reordered,q.resets,q.delaySpikes(),q.maxJitterMs,q.maxArrivalGapMs,q.reliableTimestamps?"是":"否"));
        text.append("\n").append(s.note).append("\n\n序号缺口只能说明抓包中缺包，不能直接区分网络丢包和抓包遗漏。\n到达延迟表示卡顿风险，实际听感取决于终端抖动缓冲。正常 DTX 间歇不按卡顿处理。\n\n在「质量时间点」中双击一行，可生成波形并定位音频。\n");
        if(!s.events.isEmpty())for(DtmfParser.Event e:s.events)text.append("\n按键 ").append(e.key).append(" · ").append(e.typeLabel()).append(" · ").append(e.durationText());
        showDetails(true);detail.showText("RTP 波形 / 质量",s.src+" → "+s.dst+"\nCall-ID："+s.callId,text.toString());detailTabs.setSelectedIndex(0);issues=q==null?Collections.emptyList():q.issues;
        issueTable.setModel(new AbstractTableModel(){String[] names={"时间","类型","说明"};public int getRowCount(){return issues.size();}public int getColumnCount(){return 3;}public String getColumnName(int c){return names[c];}public Object getValueAt(int r,int c){QualityAnalyzer.Issue i=issues.get(r);return new Object[]{Ui.stamp(i.timeUs),i.kind,i.description}[c];}});issueTable.getColumnModel().getColumn(2).setPreferredWidth(Ui.u(380));
    }
    private void locateIssue() {
        int n=index(issueTable);if(n<0||n>=issues.size()||inspectedStream==null)return;QualityAnalyzer.Issue issue=issues.get(n);RtpStream s=inspectedStream;
        if(!s.playable()){status("该媒体流暂不支持音频定位");return;}
        Runnable locate=()->seekTo(issueMillis(issue,s,audioStreams));if(audioStreams.contains(s)&&currentWav!=null)locate.run();else renderAudio(Collections.singletonList(s),false,locate);
    }
    public static long issueMillis(QualityAnalyzer.Issue issue,RtpStream stream,List<RtpStream> audio) {
        long origin=stream.firstUs();for(RtpStream s:audio)origin=Math.min(origin,s.firstUs());
        return Math.max(0,(stream.firstUs()-origin)/1000+(issue.clock==stream.clock?(long)((int)(issue.startTimestamp-stream.packets.get(0).timestamp)*1000.0/stream.clock):(issue.timeUs-stream.firstUs())/1000));
    }
    private void chooseFile(){JFileChooser chooser=new JFileChooser();chooser.setDialogTitle("导入 PCAP / PCAPNG · 可多选");chooser.setMultiSelectionEnabled(true);chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("抓包文件 (*.pcap, *.pcapng, *.cap)","pcap","pcapng","cap"));if(chooser.showOpenDialog(this)==JFileChooser.APPROVE_OPTION)loadFiles(Arrays.asList(chooser.getSelectedFiles()));}
    private void chooseTlsKeys(){
        if(busy||closed)return;
        Object[] actions={"导入 RSA 私钥","导入 TLS key log","清除 RSA 私钥","清除 TLS key log","取消"};
        int choice=JOptionPane.showOptionDialog(this,"已加载 RSA 私钥 "+rsaKeys.size()+" 把、TLS key log "+tlsKeys.size()+" 条，仅保留在当前会话内。\nRSA 私钥：Wireshark RSA keys list 使用的 .key / .pem / .der。\nTLS key log：CLIENT_RANDOM / TRAFFIC_SECRET 会话密钥日志。\n追加或清除后会重新分析当前抓包。","解密密钥",JOptionPane.DEFAULT_OPTION,JOptionPane.PLAIN_MESSAGE,null,actions,actions[0]);
        if(choice==2){clearRsaKeys();return;}if(choice==3){clearTlsKeys();return;}if(choice!=0&&choice!=1)return;
        JFileChooser chooser=new JFileChooser();chooser.setDialogTitle(choice==0?"单独导入未加密 RSA 私钥":"单独导入 TLS key log 文件");
        if(choice==0)chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("RSA 私钥 (*.key, *.pem, *.der)","key","pem","der"));
        if(chooser.showOpenDialog(this)==JFileChooser.APPROVE_OPTION){if(choice==0)loadRsaKey(chooser.getSelectedFile());else loadTlsKeyLog(chooser.getSelectedFile());}
    }
    public int rsaKeyCount(){return rsaKeys.size();}
    public void loadRsaKey(File file){
        if(busy||closed)return;saveCaptureView();final TlsRsaKeys previous=rsaKeys;setBusy(true,"正在读取 RSA 私钥…");
        new SwingWorker<TlsRsaKeys,Void>(){protected TlsRsaKeys doInBackground()throws Exception{try(InputStream in=new FileInputStream(file)){return previous.merge(TlsRsaKeys.read(in));}}
            protected void done(){if(closed)return;setBusy(false,"");try{rsaKeys=get();saveCaptureView();updateButtons();if(captureFiles.current()!=null)openCapture(captureFiles.activeIndex());else status("已加载 "+rsaKeys.size()+" 把 RSA 私钥，可单独导入抓包");}catch(Exception e){error(e);}}}.execute();
    }
    public void clearRsaKeys(){if(busy||closed)return;saveCaptureView();rsaKeys=TlsRsaKeys.empty();updateButtons();if(captureFiles.current()!=null)openCapture(captureFiles.activeIndex());else status("RSA 私钥已清除");}
    public int tlsKeyCount(){return tlsKeys.size();}
    public void loadTlsKeyLog(File file){
        if(busy||closed)return;saveCaptureView();final TlsKeyLog previous=tlsKeys;setBusy(true,"正在读取 TLS 会话密钥…");
        new SwingWorker<TlsKeyLog,Void>(){protected TlsKeyLog doInBackground()throws Exception{try(InputStream in=new FileInputStream(file)){return previous.merge(TlsKeyLog.read(in));}}
            protected void done(){if(closed)return;setBusy(false,"");try{tlsKeys=get();saveCaptureView();updateButtons();if(captureFiles.current()!=null)openCapture(captureFiles.activeIndex());else status("已加载 "+tlsKeys.size()+" 条 TLS 会话密钥，可单独导入抓包");}catch(Exception e){error(e);}}}.execute();
    }
    public void clearTlsKeys(){if(busy||closed)return;saveCaptureView();tlsKeys=TlsKeyLog.empty();updateButtons();if(captureFiles.current()!=null)openCapture(captureFiles.activeIndex());else status("TLS 会话密钥已清除");}
    public void load(File file) {
        if(busy||closed)return;if(file!=null){loadFiles(Collections.singletonList(file));return;}saveCaptureView();int index=captureFiles.add("demo:","演示 · G.711 / G.729 / 按键 / 丢包",null);openCapture(index);
    }
    public void loadFiles(List<File> files){
        if(busy||closed||files.isEmpty())return;saveCaptureView();int first=-1;
        for(File file:files)if(file!=null){File source=file.getAbsoluteFile().toPath().normalize().toFile();int index=captureFiles.add(source.getPath().toLowerCase(Locale.ROOT),source.getName(),source);if(first<0)first=index;}
        if(first>=0)openCapture(first);
    }
    public int captureCount(){return captureFiles.size();}
    public int captureIndex(){return captureFiles.activeIndex();}
    public void selectCapture(int index){if(busy||closed)return;saveCaptureView();openCapture(index);}
    private void saveCaptureView(){CaptureWorkspace.Entry<File> entry=captureFiles.current();if(entry==null||model.analysis==null)return;entry.query=search.getText();entry.callId=model.callId;entry.tab=tabs.getSelectedIndex();entry.callSearch=model.callSearch.copy();}
    private void updateFileSelector(){
        updatingFiles=true;fileSelector.removeAllItems();for(int i=0;i<captureFiles.size();i++)fileSelector.addItem(captureFiles.get(i));fileSelector.setSelectedIndex(captureFiles.activeIndex());updatingFiles=false;
        ((CardLayout)fileDisplay.getLayout()).show(fileDisplay,captureFiles.size()>0?"files":"empty");fileSelector.setToolTipText(captureFiles.current()==null?"切换抓包文件":captureFiles.current().id+" · 各文件独立分析");fileDisplay.revalidate();
    }
    private void clearCapture(){
        if(model.analysis!=null)try{model.analysis.close();}catch(IOException e){status("媒体缓存清理未完成");}
        closeCaptureDialogs();discardAudio();setPlayerExpanded(false);model.load(null);setCallSearch(new CallSearch.Filter());searchTimer.stop();search.setText("");searchTimer.stop();filter.setText("全部通话");issues=new ArrayList<>();inspectedStream=null;issueTable.setModel(new DefaultTableModel());detailTabs.setSelectedIndex(0);summary.setText("请选择抓包文件");fileName="";fileTitle.setText("打开抓包，查看通话");clock.setText("00:00.000 / 00:00.000");refreshViews();
    }
    private void closeCapture(){
        if(busy||captureFiles.current()==null)return;captureFiles.removeCurrent();if(captureFiles.current()!=null)openCapture(captureFiles.activeIndex());else{clearCapture();updateFileSelector();detail.showText("打开抓包","各文件独立分析","可以一次选择多个抓包，或把多个文件拖入窗口。");status("文件列表已清空，原始抓包保留");}
    }
    private void openCapture(int index){
        if(busy)return;final int previousIndex=captureFiles.activeIndex();final Analysis previous=model.analysis;pendingPrevious=previous;final String previousName=fileName;model.analysis=null;captureFiles.select(index);final CaptureWorkspace.Entry<File> entry=captureFiles.current();clearCapture();
        updateFileSelector();setBusy(true,"正在准备 "+entry.name+"…");cancelImport.setVisible(true);
        final TlsKeyLog keys=tlsKeys;final TlsRsaKeys rsa=rsaKeys;
        importTask=new SwingWorker<Analysis,String>(){
            Analysis parsed;
            protected Analysis doInBackground()throws Exception{try{
                if(entry.source!=null&&entry.source.length()>CaptureEngine.MAX_DESKTOP_FILE)throw new IOException("抓包超过 1 GiB，请先拆分文件");
                AnalysisCache cache=null;String key=null;
                if(entry.source!=null&&keys.size()==0&&rsa.size()==0){
                    publish("正在检查已有索引…");cache=new AnalysisCache(new File(System.getProperty("user.home"),".chaoge-huatan/index"));
                    try(InputStream in=new FileInputStream(entry.source)){key=cache.key(in);}
                    parsed=cache.load(key);if(parsed!=null){publish("已复用解析索引");if(isCancelled()){parsed.close();throw new java.util.concurrent.CancellationException();}return parsed;}
                }
                try(InputStream in=entry.source==null?DesktopApp.class.getResourceAsStream("/demo-analysis.pcap"):new FileInputStream(entry.source)){
                    if(in==null)throw new IOException("无法打开抓包文件");
                    parsed=CaptureEngine.readLarge(in,null,new CaptureEngine.Progress(){public void update(long bytes,long packets){publish(String.format(Locale.ROOT,"读取抓包 · %.1f / %.1f MiB · %,d 包",bytes/1048576.0,entry.source==null?bytes/1048576.0:entry.source.length()/1048576.0,packets));}public void stage(String name){publish(name+"…");}},keys,rsa);
                }
                if(isCancelled()){parsed.close();throw new java.util.concurrent.CancellationException();}
                if(cache!=null){publish("正在保存解析索引…");try{cache.save(key,parsed);}catch(IOException e){if(isCancelled()){parsed.close();throw e;}parsed.warn("索引未保存，本次分析仍可查看");}}
                if(isCancelled()){parsed.close();throw new java.util.concurrent.CancellationException();}return parsed;
                }finally{if(isCancelled()&&parsed!=null)try{parsed.close();}catch(IOException ignored){}}
            }
            protected void process(List<String> updates){if(!closed&&!updates.isEmpty())status(updates.get(updates.size()-1));}
            protected void done(){
                cancelImport.setVisible(false);if(closed){if(parsed!=null)try{parsed.close();}catch(IOException ignored){}return;}setBusy(false,"");
                try{Analysis a=get();if(previous!=null)previous.close();entry.error="";closeCaptureDialogs();discardAudio();acceptAnalysis(a,entry.name);model.callId=entry.callId;setCallSearch(entry.callSearch);setSearch(entry.query);tabs.setSelectedIndex(Math.max(0,Math.min(tabs.getTabCount()-1,entry.tab)));filter.setText(entry.callId.isEmpty()?"全部通话":"当前通话："+entry.callId);}
                catch(Exception e){if(isCancelled()){if(previousIndex>=0&&previousIndex<captureFiles.size())captureFiles.select(previousIndex);if(previous!=null){acceptAnalysis(previous,previousName);CaptureWorkspace.Entry<File> old=captureFiles.current();model.callId=old.callId;setCallSearch(old.callSearch);setSearch(old.query);tabs.setSelectedIndex(Math.min(tabs.getTabCount()-1,old.tab));}status("导入已取消，已返回原有文件");}else{if(previous!=null)try{previous.close();}catch(IOException ignored){}entry.error=Ui.error(e);detail.showText("文件未能读取",entry.name,"可在顶部切换其他抓包。\n\n"+entry.error);error(e);}}
                pendingPrevious=null;updateFileSelector();
            }
        };importTask.execute();
    }
    private void renderAudio(List<RtpStream> input,boolean autoplay,Runnable after) {
        if(busy)return;if(input.isEmpty()){status("没有可播放的媒体流");return;}
        DesktopModel selection=new DesktopModel();selection.selected.addAll(input);try{selection.playbackSelection();}catch(IllegalArgumentException e){error(e);return;}
        List<RtpStream> chosen=new ArrayList<>(input);setPlayerExpanded(true);setBusy(true,"正在还原音频和波形…");player.pause();
        new SwingWorker<AudioPreview,Void>(){File target;protected AudioPreview doInBackground() throws Exception {target=File.createTempFile("chaoge-huatan-windows-",".wav");try{return AudioPreview.render(chosen,model.analysis.events,target);}catch(Exception e){target.delete();throw e;}}
            protected void done(){if(closed){if(target!=null)target.delete();return;}setBusy(false,"");try{AudioPreview result=get();discardAudio();currentWav=target;audioStreams=chosen;waveform.setPreview(result);keySummary.setText(result.keySummary());pendingSeek=0;audioTitle.setText(result.tracks.size()==1?chosen.get(0).codec+" · "+chosen.get(0).src+" → "+chosen.get(0).dst:"双向播放 · "+result.tracks.size()+" 路独立波形");showQuality(chosen.get(0));status("音频已就绪 · 点击按键标签看详情，点击波形定位");updateButtons();revalidate();if(after!=null)after.run();if(autoplay)togglePlayback();}catch(Exception e){error(e);}}}.execute();
    }
    private void togglePlayback() {
        if(busy||currentWav==null)return;if(player.ready()){if(player.playing())player.pause();else player.play();return;}
        File wav=routedWav==null?currentWav:routedWav;setBusy(true,"正在打开音频设备…");new SwingWorker<Void,Void>(){protected Void doInBackground() throws Exception{player.load(wav);return null;}protected void done(){if(closed){player.close();return;}setBusy(false,"");try{get();player.seek(pendingSeek);player.setLoop(loopA,loopB);player.play();status("正在播放");}catch(Exception e){error(new IOException("音频设备无法打开，可先导出 WAV 使用其他播放器试听。"+Ui.error(e),e));}}}.execute();
    }
    private void showListeningOptions(){
        AudioPreview preview=waveform.preview();if(busy||preview==null)return;JPanel options=new JPanel(new GridLayout(0,1,5,5));List<JCheckBox> lanes=new ArrayList<>();
        for(int i=0;i<preview.tracks.size();i++){JCheckBox lane=new JCheckBox("播放方向 "+(i+1)+" · "+preview.tracks.get(i).label,audible==null||audible[i]);lanes.add(lane);options.add(lane);}
        JCheckBox stereo=new JCheckBox("两路分别输出左 / 右声道",stereoPlayback);options.add(stereo);JComboBox<String> speeds=new JComboBox<>(new String[]{"0.5","0.75","1.0","1.25","1.5","2.0"});speeds.setSelectedItem(String.valueOf(playbackSpeed));JPanel speedRow=new JPanel();speedRow.add(new JLabel("播放倍速"));speedRow.add(speeds);options.add(speedRow);
        JCheckBox loop=new JCheckBox("A/B 选区循环",loopA>=0);options.add(loop);JSpinner a=new JSpinner(new SpinnerNumberModel(loopA<0?pendingSeek/1000.0:loopA/1000.0,0,duration()/1000.0,.1)),b=new JSpinner(new SpinnerNumberModel(loopB<0?duration()/1000.0:Math.min(loopB,duration())/1000.0,0,duration()/1000.0,.1));JPanel region=new JPanel();region.add(new JLabel("A 秒"));region.add(a);region.add(new JLabel("B 秒"));region.add(b);options.add(region);options.add(new JLabel("取消勾选可静音；只勾选一路即独听该方向。"));
        if(JOptionPane.showConfirmDialog(this,options,"双向试听设置",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;long start=Math.round(((Number)a.getValue()).doubleValue()*1000),end=Math.round(((Number)b.getValue()).doubleValue()*1000);if(loop.isSelected()&&end<=start){status("B 点需要晚于 A 点");return;}
        boolean[] enabled=new boolean[lanes.size()];List<File> files=new ArrayList<>();List<Double> offsets=new ArrayList<>();for(int i=0;i<enabled.length;i++){enabled[i]=lanes.get(i).isSelected();files.add(preview.tracks.get(i).audio);offsets.add(preview.tracks.get(i).offsetMs);}boolean separate=stereo.isSelected();float rate=Float.parseFloat((String)speeds.getSelectedItem());boolean repeat=loop.isSelected(),resume=player.playing();long position=player.ready()?player.position():pendingSeek;player.pause();setBusy(true,"正在应用试听设置…");
        new SwingWorker<File,Void>(){File output;protected File doInBackground()throws Exception{output=File.createTempFile("huatan-listening-",".wav");try{PcmTracks.mix(files,offsets,enabled,separate,output);player.close();player.setSpeed(rate);return output;}catch(Exception e){output.delete();throw e;}}protected void done(){if(closed){if(output!=null)output.delete();return;}setBusy(false,"");try{File ready=get();if(routedWav!=null)routedWav.delete();routedWav=ready;audible=enabled;stereoPlayback=separate;playbackSpeed=rate;loopA=repeat?start:-1;loopB=repeat?end:-1;pendingSeek=repeat?start:position;status("试听设置已应用 · "+rate+"×"+(repeat?" · A/B 循环":""));if(resume)togglePlayback();}catch(Exception e){error(e);}}}.execute();
    }
    private long duration(){return waveform.data()==null?0:(long)waveform.data().durationMs();}
    private void seekTo(long ms){pendingSeek=Math.max(0,Math.min(duration(),ms));player.seek(pendingSeek);waveform.revealPosition(pendingSeek);waveform.setPosition(pendingSeek);tick();}
    private void tick(){long at=player.ready()?player.position():pendingSeek,total=duration();waveform.setPosition(at);if(!seek.getValueIsAdjusting()){updatingSeek=true;seek.setValue(total==0?0:(int)Math.min(10000,at*10000/total));updatingSeek=false;}clock.setText(Ui.clock(at)+" / "+Ui.clock(total));toggle.setText(player.playing()?"暂停":"播放 / 继续");updateCompactPlayer();}
    private void exportWav(){
        AudioPreview preview=waveform.preview();if(currentWav==null||preview==null||busy)return;
        JFileChooser chooser=new JFileChooser();chooser.setDialogTitle("导出 WAV · "+preview.tracks.size()+" 个独立声道");chooser.setSelectedFile(new File("chaoge-huatan-"+preview.tracks.size()+"ch-"+System.currentTimeMillis()+".wav"));
        if(chooser.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;File target=chooser.getSelectedFile();if(!target.getName().toLowerCase(Locale.ROOT).endsWith(".wav"))target=new File(target.getPath()+".wav");
        if(target.exists()&&JOptionPane.showConfirmDialog(this,"文件已存在，是否覆盖？","导出 WAV",JOptionPane.YES_NO_OPTION)!=JOptionPane.YES_OPTION)return;exportWav(target);
    }
    void exportWav(File target){
        final AudioPreview preview=waveform.preview();if(currentWav==null||preview==null||busy)return;final File destination=target.getAbsoluteFile();setBusy(true,"正在导出 WAV · "+preview.tracks.size()+" 个独立声道…");
        new SwingWorker<Void,Void>(){
            protected Void doInBackground()throws Exception{
                java.nio.file.Path temp=Files.createTempFile(destination.getParentFile().toPath(),".huatan-wav-",".part");
                try{preview.exportWav(temp.toFile());if(isCancelled()||Thread.currentThread().isInterrupted())throw new InterruptedIOException("导出已取消");
                    try{Files.move(temp,destination.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}catch(java.nio.file.AtomicMoveNotSupportedException unsupported){Files.move(temp,destination.toPath(),StandardCopyOption.REPLACE_EXISTING);}return null;
                }finally{Files.deleteIfExists(temp);}
            }
            protected void done(){if(closed)return;setBusy(false,"");try{get();status("WAV 已导出 · "+preview.tracks.size()+" 个独立声道："+destination.getAbsolutePath());}catch(Exception e){error(e);}}
        }.execute();
    }
    private void discardAudio(){player.close();player.setLoop(-1,-1);if(routedWav!=null)routedWav.delete();routedWav=null;audible=null;loopA=loopB=-1;if(waveform.preview()!=null)waveform.preview().close();File old=currentWav;currentWav=null;audioStreams=new ArrayList<>();pendingSeek=0;waveform.setData(null);keySummary.setText("生成波形后显示按键信息");if(old!=null&&!old.delete())old.deleteOnExit();audioTitle.setText("选择媒体流，还原音频后显示波形");}
    private void updateButtons(){importButton.setEnabled(!busy);tlsKeyButton.setEnabled(!busy);tlsKeyButton.setText(tlsKeys.size()+rsaKeys.size()==0?"解密密钥":"解密密钥 · "+(tlsKeys.size()+rsaKeys.size()));tlsKeyButton.setToolTipText("RSA 私钥 "+rsaKeys.size()+" 把 / TLS key log "+tlsKeys.size()+" 条；点击可分别导入或清除");demoButton.setEnabled(!busy);callQuick.setEnabled(!busy);callAdvanced.setEnabled(!busy);captureButton.setEnabled(!busy);fileSelector.setEnabled(!busy);closeFile.setEnabled(!busy&&captureFiles.size()>0);playSelected.setEnabled(!busy&&model.analysis!=null);toggle.setEnabled(!busy&&currentWav!=null);export.setEnabled(!busy&&currentWav!=null);updateCompactPlayer();}
    private void setBusy(boolean value,String text){busy=value;updateButtons();if(!text.isEmpty())status(text);setCursor(Cursor.getPredefinedCursor(value?Cursor.WAIT_CURSOR:Cursor.DEFAULT_CURSOR));}
    private void status(String text){status.setText(text);status.setToolTipText(text);}
    private void error(Throwable error){String message=Ui.error(error);status("操作未完成："+message);if(!GraphicsEnvironment.isHeadless())JOptionPane.showMessageDialog(this,message,"超哥话探",JOptionPane.ERROR_MESSAGE);}
    private void showWarnings(){if(model.analysis==null)return;showDetails(true);StringBuilder text=new StringBuilder();for(Map.Entry<String,Integer> e:model.analysis.warnings.entrySet())text.append(e.getKey()).append("：").append(e.getValue()).append(" 次\n\n");detail.showText("分析提示",fileName,text.toString());detailTabs.setSelectedIndex(0);}
    private String speechLicenses()throws IOException{StringBuilder text=new StringBuilder();for(String name:new String[]{"g722-LICENSE.txt","sherpa-onnx-LICENSE.txt","whisper-MIT.txt","sensevoice-MODEL-LICENSE.txt","opencc-LICENSE.txt"})try(InputStream in=getClass().getResourceAsStream("/licenses/"+name)){text.append("\n\n").append(name).append("\n").append(readText(in));}return text.toString();}
    private void about(){showDetails(true);try(InputStream in=getClass().getResourceAsStream("/licenses/libjitsi-LICENSE.txt");InputStream laf=getClass().getResourceAsStream("/licenses/flatlaf-LICENSE.txt");InputStream opus=getClass().getResourceAsStream("/licenses/concentus-LICENSE.txt");InputStream crypto=getClass().getResourceAsStream("/licenses/bouncycastle-LICENSE.txt")){detail.showText("超哥话探 · Windows "+VERSION,"Win10 / Win11 x64 · 离线分析", "支持 PCAP / PCAPNG、SIP TCP / UDP / WS、TLS / WSS 会话密钥解析，G.711 / G.729 / Opus、三类按键、双向波形和质量分析。\nRSA 私钥或 TLS key log 与抓包可分别导入，密钥仅保留在本次会话内。RSA 私钥适用于 TLS 1.0～1.2 RSA 密钥交换；ECDHE / TLS 1.3 需要 key log。SRTP 媒体暂不解密。\n\nG.729：libjitsi，Apache-2.0。\nOpus：Concentus，BSD-3-Clause。\nTLS 加密组件：Bouncy Castle，MIT。\n界面：FlatLaf，Apache-2.0。\n运行环境：Eclipse Temurin。\n\n"+readText(in)+"\n\nFlatLaf\n"+readText(laf)+"\n\nConcentus\n"+readText(opus)+"\n\nBouncy Castle\n"+readText(crypto)+speechLicenses());detailTabs.setSelectedIndex(0);}catch(IOException e){error(e);}}
    private void trackCaptureDialog(JDialog dialog){captureDialogs.add(dialog);dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);dialog.addWindowListener(new WindowAdapter(){public void windowClosed(WindowEvent e){captureDialogs.remove(dialog);}});}
    private void closeCaptureDialogs(){for(JDialog dialog:new ArrayList<>(captureDialogs))dialog.dispose();captureDialogs.clear();}
    private void expandFlow(){JDialog dialog=new JDialog((Frame)SwingUtilities.getWindowAncestor(this),"通话流序图",false);trackCaptureDialog(dialog);FlowPanel expanded=new FlowPanel();expanded.setData(model.flow());expanded.setOpenListener(o->{openEntry(o);});dialog.setContentPane(expanded.scrollPane());Ui.fitWindow(dialog,1100,760,600,400);dialog.setLocationRelativeTo(this);dialog.setVisible(true);}
    private void installDrop(){setTransferHandler(new TransferHandler(){public boolean canImport(TransferSupport s){return !busy&&s.isDataFlavorSupported(DataFlavor.javaFileListFlavor);}public boolean importData(TransferSupport s){if(!canImport(s))return false;try{List<?> values=(List<?>)s.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);List<File> files=new ArrayList<>();for(Object value:values)if(value instanceof File)files.add((File)value);if(!files.isEmpty()){loadFiles(files);return true;}}catch(Exception e){error(e);}return false;}});}
    private void captureAction(){if(captureFile!=null){stopCapture();return;}File located=CaptureSession.findTshark();if(located==null){JOptionPane.showMessageDialog(this,"本机抓包需要已安装 Wireshark 和 Npcap。\n可以选择 tshark.exe 的位置；已有抓包可直接导入。","本机抓包",JOptionPane.INFORMATION_MESSAGE);JFileChooser picker=new JFileChooser();picker.setDialogTitle("选择已安装的 tshark.exe");if(picker.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return;located=picker.getSelectedFile();}final File tshark=located;setBusy(true,"正在读取可抓包网卡…");new SwingWorker<List<String>,Void>(){protected List<String> doInBackground()throws Exception{return CaptureSession.listInterfaces(tshark);}protected void done(){if(closed)return;setBusy(false,"");try{List<String> found=get();String iface=(String)JOptionPane.showInputDialog(DesktopApp.this,"选择要抓包的网卡","本机抓包",JOptionPane.QUESTION_MESSAGE,null,found.toArray(),found.get(0));if(iface==null)return;JFileChooser chooser=new JFileChooser();chooser.setSelectedFile(new File("chaoge-huatan-capture-"+System.currentTimeMillis()+".pcapng"));if(chooser.showSaveDialog(DesktopApp.this)!=JFileChooser.APPROVE_OPTION)return;File out=chooser.getSelectedFile();if(out.exists()){JOptionPane.showMessageDialog(DesktopApp.this,"请选择一个尚不存在的文件名");return;}captureLog=File.createTempFile("chaoge-huatan-capture-",".log");capture.start(tshark,iface.substring(0,iface.indexOf('.')),out,captureLog);captureFile=out;captureButton.setText("停止抓包并导入");status("正在抓包："+out.getAbsolutePath()+" · 停止后自动导入");}catch(Exception e){error(e);}}}.execute();}
    private void stopCapture(){if(captureFile==null)return;File output=captureFile,log=captureLog;setBusy(true,"正在停止抓包…");new SwingWorker<Long,Void>(){protected Long doInBackground()throws Exception{capture.stop();return CaptureSession.finishFile(output);}protected void done(){if(closed)return;captureFile=null;captureButton.setText("本机抓包");setBusy(false,"");try{get();if(output.length()<28)throw new IOException("没有生成有效抓包。"+(log!=null&&log.isFile()?new String(Files.readAllBytes(log.toPath()),StandardCharsets.UTF_8):""));load(output);}catch(Exception e){error(e);}finally{if(log!=null&&!log.delete())log.deleteOnExit();}}}.execute();}
    public void shutdown(){closed=true;updates.close();callTools.close();if(importTask!=null)importTask.cancel(true);tlsKeys=TlsKeyLog.empty();rsaKeys=TlsRsaKeys.empty();ticker.stop();searchTimer.stop();closeCaptureDialogs();discardAudio();if(pendingPrevious!=null)try{pendingPrevious.close();}catch(IOException ignored){}if(model.analysis!=null)try{model.analysis.close();}catch(IOException ignored){}if(captureFile!=null)try{capture.stop();CaptureSession.finishFile(captureFile);}catch(Exception ignored){}if(captureLog!=null&&!captureLog.delete())captureLog.deleteOnExit();}
    private static String readText(InputStream in)throws IOException{if(in==null)throw new IOException("资源不存在");ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int n;while((n=in.read(buffer))!=-1)out.write(buffer,0,n);return new String(out.toByteArray(),StandardCharsets.UTF_8);}
    private static final class CallRenderer extends JPanel implements ListCellRenderer<Call> {
        final JLabel people=Ui.label("",13,Ui.INK),time=Ui.label("",11,Ui.MUTED),state=Ui.label("",12,Ui.POSITIVE),id=Ui.label("",11,Ui.MUTED);
        CallRenderer(){super(new GridLayout(0,1,0,Ui.u(4)));setBorder(BorderFactory.createEmptyBorder(Ui.u(10),Ui.u(9),Ui.u(10),Ui.u(9)));add(people);add(time);add(state);add(id);}
        public Component getListCellRendererComponent(JList<? extends Call> list,Call c,int index,boolean selected,boolean focus){setBackground(selected?Ui.SELECTED:Ui.PANEL);people.setText(CallSearch.participants(c));time.setText(CallSearch.times(c));state.setText((c.status.isEmpty()?"SIP":c.status)+" · "+c.sipCount+" SIP / "+c.streams.size()+" RTP");id.setText(c.id);setToolTipText(CallSearch.participants(c)+" | "+CallSearch.times(c)+" | "+c.id+" | SIP "+c.signalingIps+" | RTP "+c.mediaIps);setSize(Math.max(Ui.u(170),list.getWidth()),Ui.u(122));doLayout();return this;}
    }
    public static void main(String[] args) throws Exception {
        System.setProperty("java.net.useSystemProxies","true");
        if(args.length>=2&&args[0].equals("--diagnostics")){diagnostics(new File(args[1]));return;}
        Thread.setDefaultUncaughtExceptionHandler((thread,error)->{error.printStackTrace();SwingUtilities.invokeLater(()->JOptionPane.showMessageDialog(null,Ui.error(error),"超哥话探",JOptionPane.ERROR_MESSAGE));});
        SwingUtilities.invokeLater(()->{Ui.setup();DesktopApp app=new DesktopApp();JFrame frame=new JFrame("超哥话探 · SIP · RTP 通话分析");frame.setIconImages(Ui.icons());Workbench workbench=new Workbench(app);frame.setContentPane(workbench);Ui.fitWindow(frame,1450,920,1040,700);frame.setLocationRelativeTo(null);
            new TrayManager(frame,()->app.captureFile==null||JOptionPane.showConfirmDialog(frame,"正在抓包，停止抓包后退出？","退出超哥话探",JOptionPane.YES_NO_OPTION)==JOptionPane.YES_OPTION,()->{try{workbench.close();}finally{app.shutdown();}});
            frame.setVisible(true);app.updates.start();if(args.length>0){List<File> files=new ArrayList<>();for(String arg:args)files.add(new File(arg));app.loadFiles(files);}});
    }
    public static void diagnostics(File output) throws Exception {
        SwingUtilities.invokeAndWait(Ui::setup);
        Analysis demo;try(InputStream in=DesktopApp.class.getResourceAsStream("/demo-analysis.pcap")){demo=CaptureEngine.read(in);}List<RtpStream> audio=new ArrayList<>();for(RtpStream s:demo.streams)if(s.playable())audio.add(s);
        File wav=File.createTempFile("chaoge-huatan-diagnostics-",".wav");try{AudioPreview preview=AudioPreview.render(audio,demo.events,wav);String text="version="+VERSION+"\njava="+System.getProperty("java.version")+"\nos="+System.getProperty("os.name")+"\nui="+UIManager.getLookAndFeel().getName()+"\nsip="+demo.sip.size()+"\nstreams="+demo.streams.size()+"\nkeys="+demo.events.size()+"\nflow="+CallFlow.build(demo,"","").entries.size()+"\nwave_samples="+preview.mixed.samples+"\nwave_tracks="+preview.tracks.size()+"\n";Files.createDirectories(output.getAbsoluteFile().toPath().getParent());Files.write(output.toPath(),text.getBytes(StandardCharsets.UTF_8));}finally{if(!wav.delete())wav.deleteOnExit();}
    }
}
