package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.AudioExport.Format;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.util.Locale;

/** One WAV/MP3 save chooser used by the player and excerpt editor. */
final class AudioSaveDialog {
    static JFileChooser chooser(String title,String base,int channels){
        JFileChooser chooser=new JFileChooser();chooser.setDialogTitle(title);chooser.setAcceptAllFileFilterUsed(false);
        FileNameExtensionFilter wav=new FileNameExtensionFilter("WAV 音频 · 保留独立声道 (*.wav)","wav");
        chooser.addChoosableFileFilter(wav);
        if(channels<=2)chooser.addChoosableFileFilter(new FileNameExtensionFilter("MP3 音频 (*.mp3)","mp3"));
        chooser.setFileFilter(wav);chooser.setSelectedFile(new File(base+".wav"));
        // JFileChooser clears a selected file rejected by the new filter before its filter event.
        final File[] last={chooser.getSelectedFile()};
        chooser.addPropertyChangeListener(JFileChooser.SELECTED_FILE_CHANGED_PROPERTY,e->{if(e.getNewValue() instanceof File)last[0]=(File)e.getNewValue();});
        chooser.addPropertyChangeListener(JFileChooser.FILE_FILTER_CHANGED_PROPERTY,e->{File file=chooser.getSelectedFile();if(file==null)file=last[0];if(file!=null)chooser.setSelectedFile(extension(file,selectedFormat(chooser)));});
        return chooser;
    }
    static Format selectedFormat(JFileChooser chooser){return chooser.getFileFilter() instanceof FileNameExtensionFilter&&((FileNameExtensionFilter)chooser.getFileFilter()).accept(new File("audio.mp3"))?Format.MP3:Format.WAV;}
    static File extension(File file,Format format){return new File(file.getPath().replaceFirst("(?i)\\.(wav|mp3)$","")+"."+format.extension);}
    static File destination(JFileChooser chooser){
        File file=chooser.getSelectedFile();String name=file.getName().toLowerCase(Locale.ROOT);
        return name.endsWith(".mp3")||name.endsWith(".wav")?file:extension(file,selectedFormat(chooser));
    }
    static File choose(Component owner,String title,String base,int channels){
        JFileChooser chooser=chooser(title,base,channels);
        if(chooser.showSaveDialog(owner)!=JFileChooser.APPROVE_OPTION)return null;File target=destination(chooser);
        if(Format.of(target)==Format.MP3&&channels>2){JOptionPane.showMessageDialog(owner,"MP3 最多支持两个声道，请选择 WAV 保留全部独立声道。",title,JOptionPane.INFORMATION_MESSAGE);return null;}
        if(target.exists()&&JOptionPane.showConfirmDialog(owner,"文件已存在，是否覆盖？",title,JOptionPane.YES_NO_OPTION)!=JOptionPane.YES_OPTION)return null;
        return target;
    }
}
