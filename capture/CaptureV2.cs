// One writer owns rotation, committed boundaries, pins and metadata. Capture is independent of Java analysis.
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Globalization;

internal static partial class NativeCapture {
    sealed class CaptureDevice {internal IntPtr handle;internal int link;internal string id,label;internal uint? drops;}
    sealed class LivePacket {internal Packet packet;internal int device;}
    sealed class Volume {internal int number;internal string path;internal long bytes,packets,first=Int64.MaxValue,last;internal bool closed;}
    sealed class Pin {internal long from,to;}
    static string Number(long n){return n.ToString(CultureInfo.InvariantCulture);}
    static long RequiredNumber(Dictionary<string,string> r,string name,long min,long max){long n;if(!r.ContainsKey(name)||!Int64.TryParse(r[name],out n)||n<min||n>max)throw new IOException("抓包设置范围不正确："+name);return n;}
    static void AtomicMetadata(string path,Dictionary<string,string> values){
        values["version"]="1";var b=new StringBuilder();foreach(var p in values)b.Append(p.Key).Append('=').Append(Convert.ToBase64String(Utf8.GetBytes(p.Value))).Append('\n');
        string temp=path+".tmp";File.WriteAllText(temp,b.ToString(),Utf8);
        IOException last=null;for(int i=0;i<20;i++)try{if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);return;}catch(IOException e){int c=Marshal.GetHRForException(e)&65535;if(c!=32&&c!=33)throw;last=e;Thread.Sleep(10);}
        throw last??new IOException("抓包元数据暂时无法保存");
    }
    static void CaptureV2(Pcap api){
        var r=Read("request");int count=(int)RequiredNumber(r,"interfaces",1,8);var devices=new List<CaptureDevice>();var ids=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string task=Path.GetFullPath(r["task"]),mode=r["mode"],filter=r["filter"];
        long chunk=RequiredNumber(r,"limit",1048576,768L*1048576),budget=RequiredNumber(r,"budget",chunk,64L*1024*1048576),duration=RequiredNumber(r,"duration",0,24*60*60);
        if(mode!="single"&&mode!="rotate"&&mode!="ring")throw new IOException("保存方式不正确");if(filter.Length>4096)throw new IOException("过滤条件过长");
        using(var parent=Process.GetProcessById((int)RequiredNumber(r,"parent",1,Int32.MaxValue))){var parentHandle=parent.Handle;
            try{
                // Validate every interface and filter before making an output directory.
                for(int i=0;i<count;i++){
                    string id=r["interface."+i];if(!ids.Add(id))throw new IOException("请勿重复选择同一张网卡");var err=new StringBuilder(512);IntPtr h=api.open(id,Snaplen,1,100,err);
                    if(h==IntPtr.Zero){var fail=Status("error","无法打开网卡："+r["label."+i]+" · "+err);fail["kind"]="open";State(fail);return;}
                    var d=new CaptureDevice{handle=h,id=id,label=r["label."+i],link=api.datalink(h)};devices.Add(d);
                    if(d.link<0||d.link>65535)throw new IOException("不支持的网卡链路类型");
                    var program=new Bpf();if(!String.IsNullOrWhiteSpace(filter)){
                        if(api.compile(h,ref program,filter,1,0xffffffff)!=0){var fail=Status("error","过滤表达式无效："+Text(api.error(h)));fail["kind"]="filter";State(fail);return;}
                        try{if(api.setFilter(h,ref program)!=0)throw new IOException("无法应用过滤条件");}finally{api.freeCode(ref program);}
                    }
                    if(api.nonblock(h,1,err)!=0)throw new IOException("无法设置网卡读取方式："+err);
                }
                if(Directory.Exists(task))throw new IOException("任务目录已经存在，请重新开始抓包");Directory.CreateDirectory(task);
                var writer=new TaskWriter(task,mode,chunk,budget,duration,devices,r);var thread=new Thread(writer.Run);thread.IsBackground=true;thread.Start();
                string reason="manual",error="";long nextStats=0;
                try{
                    while(!File.Exists(Path.Combine(directory,"stop"))&&!parent.HasExited&&!writer.StopRequested){
                        bool received=false;
                        for(int i=0;i<devices.Count;i++)for(int burst=0;burst<64;burst++){
                            IntPtr header,data;int code=api.next(devices[i].handle,out header,out data);
                            if(code==0)break;if(code<0)throw new IOException("网卡读取中断："+devices[i].label+" · "+Text(api.error(devices[i].handle)));
                            received=true;int len=Marshal.ReadInt32(header,8);if(len<0||len>Snaplen)throw new IOException("网卡返回无效报文长度");
                            writer.Enqueue(i,header,data,len);
                        }
                        if(writer.Elapsed>=nextStats){foreach(var d in devices)d.drops=api.Drops(d.handle);nextStats=writer.Elapsed+500;}
                        if(duration>0&&writer.Elapsed>=duration*1000){reason="duration";break;}
                        if(!received)Thread.Sleep(2);
                    }
                    if(parent.HasExited)reason="parent";
                }catch(Exception e){reason="error";error=e.Message;}
                finally{writer.Complete(reason,error);thread.Join();}
            }finally{foreach(var d in devices)api.close(d.handle);}
        }
    }
    sealed class TaskWriter {
        readonly string task,mode;readonly long chunk,budget,duration,created=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();readonly List<CaptureDevice> devices;readonly Dictionary<string,string> request;
        readonly List<Volume> volumes=new List<Volume>();readonly Dictionary<string,Pin> pins=new Dictionary<string,Pin>();readonly Queue<LivePacket> queue=new Queue<LivePacket>();readonly object gate=new object();readonly Stopwatch clock=Stopwatch.StartNew();
        long queued,written,total,disk,queueDrops,policySkipped,nextPublish,nextCommand;int sequence;bool finished;volatile bool stopRequested;string reason="manual",readError="",lastCommand="",message="正在抓包";FileStream stream;BinaryWriter writer;Volume current;
        internal TaskWriter(string task,string mode,long chunk,long budget,long duration,List<CaptureDevice> devices,Dictionary<string,string> request){this.task=task;this.mode=mode;this.chunk=chunk;this.budget=budget;this.duration=duration;this.devices=devices;this.request=request;}
        internal bool StopRequested{get{return stopRequested;}}internal long Elapsed{get{return clock.ElapsedMilliseconds;}}
        internal void Enqueue(int device,IntPtr header,IntPtr data,int len){lock(gate){if(stopRequested)return;if(queued+len+64>QueueLimit){queueDrops++;return;}var packet=new Packet{seconds=(uint)Marshal.ReadInt32(header,0),micros=(uint)Marshal.ReadInt32(header,4),original=(uint)Marshal.ReadInt32(header,12),bytes=new byte[len]};Marshal.Copy(data,packet.bytes,0,len);queue.Enqueue(new LivePacket{packet=packet,device=device});queued+=len+64;Monitor.Pulse(gate);}}
        internal void Complete(string why,string error){lock(gate){if(!stopRequested)reason=why;readError=error;finished=true;Monitor.Pulse(gate);}}
        void Log(string text){string file=Path.Combine(task,"capture.log");if(!File.Exists(file)||new FileInfo(file).Length<262144)File.AppendAllText(file,DateTime.Now.ToString("HH:mm:ss ",CultureInfo.InvariantCulture)+text+Environment.NewLine,Utf8);}
        bool Protected(Volume v){foreach(var p in pins.Values)if(v.first<=p.to&&v.last>=p.from||v.packets==0&&p.to==Int64.MaxValue)return true;return false;}
        bool Space(long extra){
            while(disk+extra>budget&&mode=="ring"&&!File.Exists(Path.Combine(directory,"lease"))){Volume candidate=null;foreach(var v in volumes)if(v.closed&&!Protected(v)){candidate=v;break;}if(candidate==null)break;
                string full=Path.GetFullPath(candidate.path);if(Path.GetDirectoryName(full)!=task||Path.GetFileName(full)!=String.Format(CultureInfo.InvariantCulture,"capture_{0:D6}.pcapng",candidate.number)||(File.GetAttributes(full)&FileAttributes.ReparsePoint)!=0)throw new IOException("分卷路径已变化，已停止循环覆盖");
                for(int attempt=0;;attempt++)try{File.Delete(full);break;}catch(IOException e){int c=Marshal.GetHRForException(e)&65535;if((c!=32&&c!=33)||attempt>=100)throw;Thread.Sleep(10);}volumes.Remove(candidate);disk-=candidate.bytes;Log("循环覆盖第 "+candidate.number+" 卷（未保留）");
            }
            if(disk+extra<=budget)return true;stopRequested=true;reason="budget";message="任务空间达到上限，已停止；已保留的分卷未覆盖";return false;
        }
        void Open(){
            if(volumes.Count>=256||sequence>=999999){stopRequested=true;reason="volumes";message="分卷数量达到 256 个，已停止保存";return;}
            current=new Volume{number=++sequence,path=Path.Combine(task,String.Format(CultureInfo.InvariantCulture,"capture_{0:D6}.pcapng",sequence))};
            stream=new FileStream(current.path,FileMode.CreateNew,FileAccess.Write,FileShare.Read,1024*1024);writer=new BinaryWriter(stream);HeaderV2(writer,devices);writer.Flush();current.bytes=stream.Position;volumes.Add(current);disk+=current.bytes;total+=current.bytes;Log("开始写入第 "+sequence+" 卷");
        }
        void Seal(){if(writer==null)return;writer.Flush();stream.Flush(true);current.bytes=stream.Position;writer.Close();writer=null;stream=null;current.closed=true;Log("第 "+current.number+" 卷已封存");}
        Dictionary<string,string> Manifest(string phase){
            var s=Status(phase,message);s["created"]=Number(created);s["name"]=request.ContainsKey("name")?request["name"]:Path.GetFileName(task);s["task"]=task;s["mode"]=mode;s["limit"]=Number(chunk);s["budget"]=Number(budget);s["duration"]=Number(duration);s["filter"]=request["filter"];s["elapsed"]=Number(Elapsed);s["packets"]=Number(written);s["bytes"]=Number(total);s["diskBytes"]=Number(disk);s["queueDrops"]=Number(Interlocked.Read(ref queueDrops));s["policySkipped"]=Number(policySkipped);s["reason"]=reason;s["interfaces"]=Number(devices.Count);
            long drops=0;bool known=true;for(int i=0;i<devices.Count;i++){var d=devices[i];s["interface."+i]=d.id;s["label."+i]=d.label;s["link."+i]=Number(d.link);s["drops."+i]=d.drops.HasValue?Number(d.drops.Value):"";if(d.drops.HasValue)drops+=d.drops.Value;else known=false;}
            s["drops"]=known?Number(drops):"";s["volumes"]=Number(volumes.Count);for(int i=0;i<volumes.Count;i++){var v=volumes[i];string p="volume."+i+".";s[p+"number"]=Number(v.number);s[p+"file"]=Path.GetFileName(v.path);s[p+"bytes"]=Number(v.bytes);s[p+"packets"]=Number(v.packets);s[p+"first"]=Number(v.first);s[p+"last"]=Number(v.last);s[p+"closed"]=v.closed?"1":"0";s[p+"pinned"]=Protected(v)?"1":"0";}
            s["pins"]=Number(pins.Count);int at=0;foreach(var p in pins){s["pin."+at+".id"]=p.Key;s["pin."+at+".from"]=Number(p.Value.from);s["pin."+at+".to"]=Number(p.Value.to);at++;}return s;
        }
        void Publish(string phase){if(writer!=null){writer.Flush();current.bytes=stream.Position;}var s=Manifest(phase);try{AtomicMetadata(Path.Combine(task,"task"),s);}catch(IOException e){int c=Marshal.GetHRForException(e)&65535;if(c!=32&&c!=33)throw;}var status=new Dictionary<string,string>(s);status.Remove("filter");State(status);nextPublish=Elapsed+350;}
        void Commands(){
            if(Elapsed<nextCommand)return;nextCommand=Elapsed+100;if(!File.Exists(Path.Combine(directory,"command")))return;Dictionary<string,string> command;try{command=Read("command");}catch(IOException){return;}string id=command["id"];if(id==lastCommand)return;
            try{
                string action=command["action"];
                if(action=="pin"){if(pins.Count>=256&&!pins.ContainsKey(command["call"]))throw new IOException("最多保留 256 通电话");pins[command["call"]]=new Pin{from=RequiredNumber(command,"from",0,Int64.MaxValue),to=RequiredNumber(command,"to",0,Int64.MaxValue)};Log("保留通话 "+command["call"]);}
                else if(action=="unpin"){pins.Remove(command["call"]);Log("取消通话保留 "+command["call"]);}
                else if(action!="freeze")throw new IOException("不支持的抓包控制动作");
                Publish("running");var reply=Manifest("running");reply["id"]=id;reply["ok"]="1";AtomicMetadata(Path.Combine(directory,"reply"),reply);
            }catch(Exception e){AtomicMetadata(Path.Combine(directory,"reply"),new Dictionary<string,string>{{"id",id},{"ok","0"},{"message",e.Message}});}lastCommand=id;
        }
        internal void Run(){
            Exception failure=null;try{
                Open();Publish("running");
                while(true){Commands();LivePacket item=null;lock(gate){if(queue.Count==0&&!finished)Monitor.Wait(gate,50);if(queue.Count>0){item=queue.Dequeue();queued-=item.packet.bytes.Length+64;}else if(finished)break;}
                    if(item!=null){
                        if(stopRequested){policySkipped++;continue;}
                        if(current.bytes>=chunk){if(mode=="single"){stopRequested=true;reason="limit";message="文件已达到上限，自动停止";policySkipped++;continue;}Seal();if(!Space(HeaderSizeV2(devices)+32+item.packet.bytes.Length)){policySkipped++;continue;}Open();if(stopRequested){policySkipped++;continue;}}
                        long block=32+((item.packet.bytes.Length+3)&~3);if(!Space(block)){policySkipped++;continue;}
                        BlockV2(writer,item.packet,item.device);long actual=stream.Position-current.bytes;current.bytes=stream.Position;disk+=actual;total+=actual;written++;current.packets++;long time=(long)item.packet.seconds*1000000+item.packet.micros;current.first=Math.Min(current.first,time);current.last=Math.Max(current.last,time);
                    }
                    if(Elapsed>=nextPublish)Publish("running");
                }
            }catch(Exception e){failure=e;stopRequested=true;reason="error";message="写入或任务管理中断："+e.Message;}
            finally{try{Seal();}catch(Exception e){failure=e;message="保存中断："+e.Message;}if(failure==null&&!String.IsNullOrEmpty(readError)){failure=new IOException(readError);message="抓包中断："+readError;}if(failure==null&&!stopRequested)message=reason=="duration"?"已到指定时长，抓包已保存":reason=="parent"?"主程序已退出，抓包已保存":"抓包已停止，文件已保存";try{Log(message);Publish(failure==null?"done":"error");}catch{}stopRequested=true;}
        }
    }
    static byte[] InterfaceV2(CaptureDevice d){using(var m=new MemoryStream())using(var b=new BinaryWriter(m)){b.Write((ushort)d.link);b.Write((ushort)0);b.Write((uint)Snaplen);byte[] name=Utf8.GetBytes(d.label+" · "+d.id);b.Write((ushort)2);b.Write((ushort)name.Length);b.Write(name);while(m.Position%4!=0)b.Write((byte)0);b.Write((ushort)0);b.Write((ushort)0);return m.ToArray();}}
    static long HeaderSizeV2(List<CaptureDevice> devices){long n=28;foreach(var d in devices)n+=12+InterfaceV2(d).Length;return n;}
    static void HeaderV2(BinaryWriter w,List<CaptureDevice> devices){w.Write((uint)0x0a0d0d0a);w.Write((uint)28);w.Write((uint)0x1a2b3c4d);w.Write((ushort)1);w.Write((ushort)0);w.Write((long)-1);w.Write((uint)28);foreach(var d in devices){byte[] body=InterfaceV2(d);w.Write((uint)1);w.Write((uint)(body.Length+12));w.Write(body);w.Write((uint)(body.Length+12));}}
    static void BlockV2(BinaryWriter w,Packet packet,int device){uint size=(uint)(32+((packet.bytes.Length+3)&~3));ulong stamp=(ulong)packet.seconds*1000000+packet.micros;w.Write((uint)6);w.Write(size);w.Write((uint)device);w.Write((uint)(stamp>>32));w.Write((uint)stamp);w.Write((uint)packet.bytes.Length);w.Write(packet.original);w.Write(packet.bytes);for(int i=packet.bytes.Length;i%4!=0;i++)w.Write((byte)0);w.Write(size);}
}
