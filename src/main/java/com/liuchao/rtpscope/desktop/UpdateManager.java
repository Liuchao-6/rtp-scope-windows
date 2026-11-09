package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.URI;
import java.util.concurrent.*;

/** Update I/O has its own daemon worker and never blocks capture analysis or the UI. */
final class UpdateManager implements AutoCloseable {
    interface Source { UpdateChecker.Release fetch()throws Exception; }
    interface Browser { void open(URI uri)throws Exception; }
    private final Component owner;
    private final UpdateSettings settings;
    private final Source source;
    private final Browser browser;
    private final ExecutorService worker=Executors.newSingleThreadExecutor(task->{Thread thread=new Thread(task,"huatan-update-check");thread.setDaemon(true);return thread;});
    private final javax.swing.Timer startup;
    private Future<?> task;
    private boolean closed,running,manualRequested,dismissed;
    private UpdateChecker.Release available;
    private JDialog dialog;
    private final View view;

    UpdateManager(Component owner){this(owner,UpdateSettings.load(),()->new UpdateChecker().fetch(),uri->Desktop.getDesktop().browse(uri));}
    UpdateManager(Component owner,UpdateSettings settings,Source source,Browser browser){
        this.owner=owner;this.settings=settings;this.source=source;this.browser=browser;
        view=new View(settings.automatic(),()->check(true),this::download,this::dismiss,this::ignore,this::automatic);
        startup=new javax.swing.Timer(3000,e->check(false));startup.setRepeats(false);
    }
    void start(){if(!closed)startup.restart();}
    boolean automatic(){return settings.automatic();}
    void automatic(boolean enabled){
        try{settings.automatic(enabled);}catch(IOException e){view.message.setText("设置仅对本次运行生效，无法保存到用户目录。");}
        view.automatic.setSelected(enabled);
    }
    void check(boolean manual){
        if(closed)return;
        if(running){if(manual){manualRequested=true;dismissed=false;show();}return;}
        long now=System.currentTimeMillis();if(!manual&&!settings.due(now))return;
        running=true;manualRequested=manual;dismissed=false;available=null;view.checking();if(manual)show();
        task=worker.submit(()->{
            UpdateChecker.Release release=null;Exception error=null;
            try{try{settings.attempted(now);}catch(IOException ignored){/* Still allow a check if settings cannot be saved. */}release=source.fetch();}catch(Exception e){error=e;}
            final UpdateChecker.Release result=release;final Exception failure=error;
            SwingUtilities.invokeLater(()->complete(result,failure));
        });
    }
    private void complete(UpdateChecker.Release release,Exception failure){
        if(closed)return;running=false;
        if(failure!=null){view.failed();if(manualRequested&&!dismissed)show();return;}
        if(release==null){view.failed();if(manualRequested&&!dismissed)show();return;}
        available=release;boolean newer=release.newerThan(DesktopApp.VERSION);view.result(release,newer);
        if(!dismissed&&(manualRequested||newer&&!settings.ignored(release)))show();
    }
    private void show(){
        if(GraphicsEnvironment.isHeadless())return;
        if(dialog==null){
            dialog=new JDialog(SwingUtilities.getWindowAncestor(owner),"软件更新",Dialog.ModalityType.MODELESS);
            dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);dialog.setIconImages(Ui.icons());dialog.setContentPane(view);
            dialog.addWindowListener(new WindowAdapter(){public void windowClosing(WindowEvent event){dismissed=true;}public void windowClosed(WindowEvent event){if(dialog==event.getWindow())dialog=null;}});
            Ui.fitWindow(dialog,650,540,600,440);dialog.setLocationRelativeTo(owner);
        }
        if(!dialog.isVisible())dialog.setVisible(true);else if(manualRequested)dialog.toFront();
    }
    private void dismiss(){dismissed=true;if(dialog!=null){JDialog old=dialog;dialog=null;old.dispose();}}
    private void ignore(){
        if(available==null)return;
        try{settings.ignore(available);dismiss();}catch(IOException e){view.message.setText("本次已忽略，但无法保存设置；下次启动可能再次提醒。");}
    }
    private void download(){
        URI page=available==null?URI.create(UpdateChecker.RELEASES+"/latest"):available.page;
        try{browser.open(page);}catch(Exception e){view.message.setText("无法打开浏览器，可复制下方地址手动下载。");view.notes.setText(page.toString());}
    }
    public void close(){closed=true;startup.stop();if(task!=null)task.cancel(true);worker.shutdownNow();dismiss();}

    /** Plain text release notes, with stable controls for manual checks and automatic reminders. */
    static final class View extends JPanel {
        final JLabel heading=Ui.label("检查软件更新",20,Ui.INK),latest=Ui.label("等待查询",15,Ui.INK),message=Ui.label("",12,Ui.MUTED);
        final JTextArea notes=Ui.note("");
        final JButton retry=Ui.button("重新检查",false),download=Ui.button("前往下载",true),later=Ui.button("稍后提醒",false),ignore=Ui.button("忽略此版本",false);
        final JCheckBox automatic=new JCheckBox("启动时检查更新（每 24 小时最多一次）");
        View(boolean enabled,Runnable check,Runnable open,Runnable dismiss,Runnable skip,java.util.function.Consumer<Boolean> toggle){
            super(new BorderLayout(0,Ui.u(14)));setBackground(Ui.BG);setBorder(BorderFactory.createEmptyBorder(Ui.u(20),Ui.u(20),Ui.u(16),Ui.u(20)));
            heading.setIcon(new ImageIcon(Ui.icon().getScaledInstance(Ui.u(32),Ui.u(32),Image.SCALE_SMOOTH)));heading.setIconTextGap(Ui.u(10));
            JPanel top=new JPanel(new BorderLayout(0,Ui.u(14)));top.setOpaque(false);top.add(heading,BorderLayout.NORTH);
            JPanel versions=new JPanel(new GridLayout(1,2,Ui.u(12),0));versions.setOpaque(false);
            JPanel current=Ui.card(new BorderLayout(0,Ui.u(6)));current.add(Ui.label("当前版本",12,Ui.MUTED),BorderLayout.NORTH);current.add(Ui.label("Windows "+DesktopApp.VERSION,15,Ui.INK),BorderLayout.CENTER);
            JPanel remote=Ui.card(new BorderLayout(0,Ui.u(6)));remote.add(Ui.label("GitHub 正式版",12,Ui.MUTED),BorderLayout.NORTH);remote.add(latest,BorderLayout.CENTER);versions.add(current);versions.add(remote);top.add(versions,BorderLayout.CENTER);top.add(message,BorderLayout.SOUTH);add(top,BorderLayout.NORTH);
            JPanel body=new JPanel(new BorderLayout(0,Ui.u(6)));body.setOpaque(false);body.add(Ui.label("更新说明",13,Ui.INK),BorderLayout.NORTH);notes.setName("updateNotes");notes.setForeground(Ui.INK);notes.setMargin(new Insets(Ui.u(10),Ui.u(10),Ui.u(10),Ui.u(10)));body.add(Ui.scroll(notes),BorderLayout.CENTER);add(body,BorderLayout.CENTER);
            JPanel footer=new JPanel(new BorderLayout(0,Ui.u(8)));footer.setOpaque(false);JPanel options=new JPanel(new BorderLayout(0,Ui.u(6)));options.setOpaque(false);
            automatic.setOpaque(false);automatic.setSelected(enabled);automatic.setFont(Ui.font(12));automatic.setName("automaticUpdates");options.add(automatic,BorderLayout.NORTH);
            JTextArea explanation=Ui.note("仅向 GitHub 查询公开版本信息，抓包、录音和密钥均留在本机。\n新版以便携 ZIP 提供：完整解压到新目录，关闭旧版后运行。");explanation.setOpaque(false);options.add(explanation,BorderLayout.CENTER);footer.add(options,BorderLayout.NORTH);
            JPanel buttons=new JPanel(new FlowLayout(FlowLayout.RIGHT,Ui.u(6),0));buttons.setOpaque(false);for(JButton button:new JButton[]{retry,ignore,later,download})buttons.add(button);footer.add(buttons,BorderLayout.SOUTH);add(footer,BorderLayout.SOUTH);
            retry.setName("retryUpdateCheck");download.setName("downloadUpdate");ignore.setName("ignoreUpdate");later.setName("dismissUpdate");retry.addActionListener(e->check.run());download.addActionListener(e->open.run());later.addActionListener(e->dismiss.run());ignore.addActionListener(e->skip.run());automatic.addActionListener(e->toggle.accept(automatic.isSelected()));
        }
        void checking(){heading.setText("正在检查更新…");latest.setText("查询中…");message.setText("正在连接 GitHub，可继续使用其他功能。");notes.setText("");retry.setEnabled(false);download.setVisible(false);ignore.setVisible(false);later.setText("关闭");}
        void failed(){heading.setText("暂时无法检查更新");latest.setText("未获取到版本");message.setText("请检查网络或代理设置，也可直接打开发布页。");notes.setText("无法连接 GitHub，或版本信息暂不可用。\n\n检查失败不会影响本地分析；稍后可以重新检查。\n\n"+UpdateChecker.RELEASES+"/latest");retry.setEnabled(true);download.setText("打开发布页");download.setVisible(true);ignore.setVisible(false);later.setText("关闭");}
        void result(UpdateChecker.Release release,boolean newer){
            heading.setText(newer?"发现新版本":"当前无需更新");latest.setText("Windows "+release.version);message.setText(newer?"新版已发布，可查看说明后前往下载。":"当前版本已是最新正式版，或高于已发布版本。");
            notes.setText(release.title+"\n\n"+release.notes);notes.setCaretPosition(0);retry.setEnabled(true);download.setText(newer?"前往下载":"打开发布页");download.setVisible(true);ignore.setVisible(newer);later.setText(newer?"稍后提醒":"关闭");revalidate();repaint();
        }
    }
}
