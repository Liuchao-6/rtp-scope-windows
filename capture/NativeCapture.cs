// Application-owned Npcap client. No Npcap binaries or SDK files are redistributed.
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
using System.Security.Principal;

[assembly: System.Reflection.AssemblyTitle("超哥话探 · 本机抓包组件")]
[assembly: System.Reflection.AssemblyVersion("0.10.0.0")]
internal static partial class NativeCapture {
    const int Snaplen=262144;
    const long QueueLimit=32L*1024*1024;
    static string directory;
    static long revision;
    static readonly Encoding Utf8=new UTF8Encoding(false,true);
    static Dictionary<string,string> Read(string name) {
        string path=Path.Combine(directory,name);if(new FileInfo(path).Length>65536)throw new IOException("控制文件过大");
        var result=new Dictionary<string,string>();foreach(string line in File.ReadAllLines(path,Utf8)) {int p=line.IndexOf('=');if(p>0)result.Add(line.Substring(0,p),Utf8.GetString(Convert.FromBase64String(line.Substring(p+1))));}
        if(result["version"]!="1")throw new IOException("抓包组件协议版本不匹配");return result;
    }
    static void State(Dictionary<string,string> state) {
        state["version"]="1";state["revision"]=(++revision).ToString(System.Globalization.CultureInfo.InvariantCulture);
        var text=new StringBuilder();foreach(var pair in state)text.Append(pair.Key).Append('=').Append(Convert.ToBase64String(Utf8.GetBytes(pair.Value))).Append('\n');
        string temp=Path.Combine(directory,"state.tmp"),target=Path.Combine(directory,"state");File.WriteAllText(temp,text.ToString(),Utf8);
        // Windows readers can briefly deny replacement. Metadata contention must
        // not interrupt packet writing; keep the previous complete snapshot.
        for(int attempt=0;attempt<10;attempt++)try{if(File.Exists(target))File.Replace(temp,target,null);else File.Move(temp,target);return;}
            catch(IOException e){int code=Marshal.GetHRForException(e)&65535;if(code!=32&&code!=33)throw;Thread.Sleep(10);}
    }
    static Dictionary<string,string> Status(string phase,string message) {return new Dictionary<string,string>{{"phase",phase},{"message",message}};}
    static string Quote(string value) {
        var b=new StringBuilder("\"");int n=0;foreach(char c in value){if(c=='\\'){n++;continue;}if(c=='"')b.Append('\\',n*2+1);else b.Append('\\',n);b.Append(c);n=0;}b.Append('\\',n*2).Append('"');return b.ToString();
    }
    [STAThread] static int Main(string[] args) {
        if(args.Length!=2)return 2;directory=Path.GetFullPath(args[1]);
        try {
            if(args[0]=="--elevate") {
                try {var start=new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,"--capture "+Quote(directory));start.UseShellExecute=true;start.Verb="runas";start.WindowStyle=ProcessWindowStyle.Hidden;
                    using(var child=Process.Start(start)){child.WaitForExit();return child.ExitCode;}
                }catch(System.ComponentModel.Win32Exception e){var s=Status("error",e.NativeErrorCode==1223?"已取消管理员授权":"管理员授权未完成："+e.Message);s["kind"]="authorization";State(s);return 1;}
            }
            using(var api=new Pcap()) {
                if(args[0]=="--probe")Probe(api);else if(args[0]=="--capture"){if(Read("request").ContainsKey("mode"))CaptureV2(api);else Capture(api);}else return 2;
            }return 0;
        }catch(Exception e){try {var s=Status("error",e.Message);s["kind"]=e is DllNotFoundException?"driver":"capture";State(s);}catch{}return 1;}
    }
    static string Text(IntPtr p){return p==IntPtr.Zero?"":Marshal.PtrToStringAnsi(p);}
    static void Probe(Pcap api) {
        IntPtr head;var error=new StringBuilder(512);if(api.find(ref error,out head)!=0)throw new IOException(error.ToString());
        var s=Status("ready","Npcap 已就绪");int i=0;
        try {
            var adapters=NetworkInterface.GetAllNetworkInterfaces();
            for(IntPtr p=head;p!=IntPtr.Zero&&i<256;) {
                var dev=(Device)Marshal.PtrToStructure(p,typeof(Device));string id=Text(dev.name),label=Text(dev.description),addresses="",status="状态未知";
                foreach(var adapter in adapters)if(id.IndexOf(adapter.Id,StringComparison.OrdinalIgnoreCase)>=0) {
                    label=adapter.Name;status=adapter.OperationalStatus==OperationalStatus.Up?"已连接":"未连接";
                    try{foreach(var address in adapter.GetIPProperties().UnicastAddresses) {if(addresses.Length>0)addresses+="  ";addresses+=address.Address.ToString();}}catch(NetworkInformationException){}break;
                }
                if(id.IndexOf("Loopback",StringComparison.OrdinalIgnoreCase)>=0){label="本机回环（Loopback）";addresses="127.0.0.1  ::1";status="本机通信";}
                s["id."+i]=id;s["label."+i]=String.IsNullOrEmpty(label)?id:label;s["addresses."+i]=addresses;s["status."+i]=status;i++;p=dev.next;
            }
        }finally{api.free(head);}s["count"]=i.ToString();State(s);
    }
    sealed class Packet {internal byte[] bytes;internal uint seconds,micros,original;}
    static void Capture(Pcap api) {
        var request=Read("request");string iface=request["interface"],filter=request["filter"],output=Path.GetFullPath(request["output"]);
        long limit=Int64.Parse(request["limit"]);if(limit<1048576||limit>768L*1024*1024)throw new IOException("无效的文件大小上限");
        int parentId=Int32.Parse(request["parent"]);using(var parent=Process.GetProcessById(parentId)) {
            // Retain a process handle, so a reused PID cannot keep an orphan capture running.
            var handle=parent.Handle;var err=new StringBuilder(512);IntPtr capture=api.open(iface,Snaplen,1,100,err);
            if(capture==IntPtr.Zero){var failure=Status("error","无法打开网卡："+err);failure["kind"]="open";State(failure);return;}
            try {
                var program=new Bpf();if(!String.IsNullOrWhiteSpace(filter)) {
                    if(api.compile(capture,ref program,filter,1,0xffffffff)!=0){var failure=Status("error","过滤表达式无效："+Text(api.error(capture)));failure["kind"]="filter";State(failure);return;}
                    try{if(api.setFilter(capture,ref program)!=0)throw new IOException("无法应用过滤："+Text(api.error(capture)));}finally{api.freeCode(ref program);}
                }
                if(api.nonblock(capture,1,err)!=0)throw new IOException("无法设置网卡读取模式："+err);
                int link=api.datalink(capture);if(link<0||link>65535)throw new IOException("不支持的网卡数据链路类型");
                Directory.CreateDirectory(Path.GetDirectoryName(output));
                using(var stream=new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.Read,1024*1024))
                using(var writer=new BinaryWriter(stream)) {
                    Header(writer,(ushort)link);writer.Flush();
                    var queue=new Queue<Packet>();object gate=new object();long queued=0,written=0,bytes=48,queueDrops=0;bool finished=false;int sizeReached=0;Exception writeError=null;
                    var thread=new Thread(delegate(){try{while(true){Packet packet;lock(gate){while(queue.Count==0&&!finished)Monitor.Wait(gate,100);if(queue.Count==0&&finished)break;packet=queue.Dequeue();queued-=packet.bytes.Length+64;}
                                if(Thread.VolatileRead(ref sizeReached)!=0)continue;Block(writer,packet);Interlocked.Increment(ref written);Interlocked.Exchange(ref bytes,stream.Position);
                                if(stream.Position>=limit)Interlocked.Exchange(ref sizeReached,1);
                            }writer.Flush();stream.Flush(true);
                        }catch(Exception e){Interlocked.Exchange(ref writeError,e);}});thread.IsBackground=true;thread.Start();
                    var clock=Stopwatch.StartNew();long next=0;uint? drops=null;string reason="manual";Exception readError=null;
                    try {
                        while(!File.Exists(Path.Combine(directory,"stop"))&&!parent.HasExited&&Thread.VolatileRead(ref sizeReached)==0&&Interlocked.CompareExchange(ref writeError,null,null)==null) {
                            IntPtr header,data;int code=api.next(capture,out header,out data);
                            if(code==1){int length=Marshal.ReadInt32(header,8);if(length<0||length>Snaplen)throw new IOException("网卡返回无效报文长度");
                                lock(gate){if(queued+length+64>QueueLimit)Interlocked.Increment(ref queueDrops);else {var packet=new Packet{seconds=(uint)Marshal.ReadInt32(header,0),micros=(uint)Marshal.ReadInt32(header,4),original=(uint)Marshal.ReadInt32(header,12),bytes=new byte[length]};Marshal.Copy(data,packet.bytes,0,length);queue.Enqueue(packet);queued+=length+64;Monitor.Pulse(gate);}}
                            }else if(code==-1)throw new IOException("读取网卡失败："+Text(api.error(capture)));else if(code==-2){reason="device";break;}else Thread.Sleep(3);
                            if(clock.ElapsedMilliseconds>=next){drops=api.Drops(capture);SaveStats("running","正在抓包",output,clock.ElapsedMilliseconds,Interlocked.Read(ref written),Interlocked.Read(ref bytes),drops,Interlocked.Read(ref queueDrops),"");next=clock.ElapsedMilliseconds+300;}
                        }
                        if(Thread.VolatileRead(ref sizeReached)!=0)reason="limit";else if(parent.HasExited)reason="parent";
                    }catch(Exception e){readError=e;reason="error";}
                    finally {try{SaveStats("stopping","正在保存文件",output,clock.ElapsedMilliseconds,Interlocked.Read(ref written),Interlocked.Read(ref bytes),drops,Interlocked.Read(ref queueDrops),reason);}catch{}finally{lock(gate){finished=true;Monitor.Pulse(gate);}thread.Join();}}
                    // Disposing the file precedes the terminal state, including exceptional partial files.
                    writer.Close();
                    if(Thread.VolatileRead(ref sizeReached)!=0)reason="limit";
                    string message=writeError!=null?"写入中断："+writeError.Message:readError!=null?"抓包中断："+readError.Message:Thread.VolatileRead(ref sizeReached)!=0?"已达到文件上限，自动停止":"抓包已停止，文件已保存";
                    SaveStats(writeError!=null||readError!=null?"error":"done",message,output,clock.ElapsedMilliseconds,Interlocked.Read(ref written),Interlocked.Read(ref bytes),api.Drops(capture),Interlocked.Read(ref queueDrops),reason);
                }
            }finally{api.close(capture);}
        }
    }
    static void SaveStats(string phase,string message,string output,long elapsed,long packets,long bytes,uint? drops,long queueDrops,string reason) {
        var s=Status(phase,message);s["output"]=output;s["elapsed"]=elapsed.ToString();s["packets"]=packets.ToString();s["bytes"]=bytes.ToString();s["drops"]=drops.HasValue?drops.Value.ToString():"";s["queueDrops"]=queueDrops.ToString();s["reason"]=reason;State(s);
    }
    static void Header(BinaryWriter w,ushort link){w.Write((uint)0x0a0d0d0a);w.Write((uint)28);w.Write((uint)0x1a2b3c4d);w.Write((ushort)1);w.Write((ushort)0);w.Write((long)-1);w.Write((uint)28);w.Write((uint)1);w.Write((uint)20);w.Write(link);w.Write((ushort)0);w.Write((uint)Snaplen);w.Write((uint)20);}
    static void Block(BinaryWriter w,Packet packet){uint size=(uint)(32+((packet.bytes.Length+3)&~3));ulong stamp=(ulong)packet.seconds*1000000+packet.micros;w.Write((uint)6);w.Write(size);w.Write((uint)0);w.Write((uint)(stamp>>32));w.Write((uint)stamp);w.Write((uint)packet.bytes.Length);w.Write(packet.original);w.Write(packet.bytes);for(int i=packet.bytes.Length;i%4!=0;i++)w.Write((byte)0);w.Write(size);}
    [StructLayout(LayoutKind.Sequential)] struct Device {public IntPtr next,name,description,addresses;public uint flags;}
    [StructLayout(LayoutKind.Sequential)] struct Bpf {public uint length;public IntPtr instructions;}
    sealed class Pcap:IDisposable {
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibraryEx(string path,IntPtr file,uint flags);
        [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module,string name);
        [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Find(out IntPtr list,StringBuilder error);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void Free(IntPtr list);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Ansi)] internal delegate IntPtr Open(string id,int snap,int promisc,int timeout,StringBuilder error);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Ansi)] internal delegate int Compile(IntPtr p,ref Bpf program,string filter,int optimize,uint mask);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int SetFilter(IntPtr p,ref Bpf program);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void FreeCode(ref Bpf program);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Nonblock(IntPtr p,int value,StringBuilder err);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Next(IntPtr p,out IntPtr header,out IntPtr data);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Datalink(IntPtr p);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr Error(IntPtr p);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Stats(IntPtr p,IntPtr stats);
        IntPtr module;Find findAll;internal Free free,close;internal Open open;internal Compile compile;internal SetFilter setFilter;internal FreeCode freeCode;internal Nonblock nonblock;internal Next next;internal Datalink datalink;internal Error error;Stats stats;
        T Load<T>(string name) where T:class {var symbol=GetProcAddress(module,name);if(symbol==IntPtr.Zero)throw new IOException("Npcap 接口不可用："+name);return Marshal.GetDelegateForFunctionPointer(symbol,typeof(T)) as T;}
        internal Pcap(){string path=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"Npcap","wpcap.dll");module=LoadLibraryEx(path,IntPtr.Zero,0x100|0x800);if(module==IntPtr.Zero)throw new DllNotFoundException("未检测到可用的 Npcap，请从官网安装后重新检测；已有文件仍可分析。");
            findAll=Load<Find>("pcap_findalldevs");free=Load<Free>("pcap_freealldevs");open=Load<Open>("pcap_open_live");close=Load<Free>("pcap_close");compile=Load<Compile>("pcap_compile");setFilter=Load<SetFilter>("pcap_setfilter");freeCode=Load<FreeCode>("pcap_freecode");nonblock=Load<Nonblock>("pcap_setnonblock");next=Load<Next>("pcap_next_ex");datalink=Load<Datalink>("pcap_datalink");error=Load<Error>("pcap_geterr");stats=Load<Stats>("pcap_stats");}
        internal int find(ref StringBuilder error,out IntPtr head){return findAll(out head,error);}
        internal uint? Drops(IntPtr p){IntPtr buffer=Marshal.AllocHGlobal(256);try{if(stats(p,buffer)!=0)return null;return (uint)Marshal.ReadInt32(buffer,4);}finally{Marshal.FreeHGlobal(buffer);}}
        public void Dispose(){if(module!=IntPtr.Zero){FreeLibrary(module);module=IntPtr.Zero;}}
    }
}
