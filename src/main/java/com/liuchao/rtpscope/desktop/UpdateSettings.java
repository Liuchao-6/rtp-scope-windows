package com.liuchao.rtpscope.desktop;

import java.io.*;
import java.nio.file.*;
import java.util.Properties;

/** Local update preferences; independent of captures, keys and speech models. */
final class UpdateSettings {
    static final long DAY=24L*60*60*1000;
    private final Path path;
    private boolean automatic=true;
    private long lastAttempt;
    private String ignored="";

    UpdateSettings(Path path){
        this.path=path;Properties data=new Properties();
        try(InputStream in=Files.newInputStream(path)){
            data.load(in);automatic=Boolean.parseBoolean(data.getProperty("automatic","true"));ignored=data.getProperty("ignored","");
            lastAttempt=Math.max(0,Long.parseLong(data.getProperty("lastAttempt","0")));
        }catch(IOException|IllegalArgumentException ignoredError){/* Missing/damaged preferences use safe defaults. */}
    }
    static UpdateSettings load(){return new UpdateSettings(Paths.get(System.getProperty("user.home"),".chaoge-huatan","update.properties"));}
    synchronized boolean automatic(){return automatic;}
    synchronized boolean due(long now){return automatic&&(lastAttempt==0||now<lastAttempt||now-lastAttempt>=DAY);}
    synchronized boolean ignored(UpdateChecker.Release release){return ignored.equals(release.version);}
    synchronized void automatic(boolean enabled)throws IOException{automatic=enabled;save();}
    synchronized void attempted(long now)throws IOException{lastAttempt=now;save();}
    synchronized void ignore(UpdateChecker.Release release)throws IOException{ignored=release.version;save();}
    private void save()throws IOException {
        Properties data=new Properties();data.setProperty("automatic",Boolean.toString(automatic));data.setProperty("lastAttempt",Long.toString(lastAttempt));data.setProperty("ignored",ignored);
        Path parent=path.toAbsolutePath().getParent();Files.createDirectories(parent);Path temp=Files.createTempFile(parent,"update-",".tmp");
        try{
            try(OutputStream out=Files.newOutputStream(temp)){data.store(out,"ChaogeHuatan update preferences");}
            try{Files.move(temp,path,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}catch(AtomicMoveNotSupportedException e){Files.move(temp,path,StandardCopyOption.REPLACE_EXISTING);}
        }finally{Files.deleteIfExists(temp);}
    }
}
