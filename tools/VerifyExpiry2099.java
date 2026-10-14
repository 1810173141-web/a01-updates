import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.zip.*;

/** Final-APK DEX gate with pinned R4 method fingerprints and optional integrity verification.
 * APK v2/v3 certificate verification remains a separate mandatory apksigner step.
 */
class VerifyExpiry2099 {
    static final String HELPER="Llocal/runner/LocalStateTest;";
    static final String INSTALL=HELPER+"->install(Landroid/content/Context;)V";
    static final String TRUSTED_R4="1e50f3c0be0a804e57482cd4775eebc4214b6fa0b134725613ae2f251ce8a90a";
    static final String TRUSTED_CERT="25280080e854bc7fbbcae86b89b3d7cc0d66d9c1925454f4d97fd4e0eadf8369";
    static final Map<String,String> PINNED=Map.ofEntries(
        Map.entry("Llocal/runner/LocalStateTest;->install(Landroid/content/Context;)V","4802feb7eec582ca758338e1a389a9dff519b0dcc6847c4eeccfd079da8cd75a"),
        Map.entry("Llocal/runner/e8;->j(Ljava/io/File;Llocal/runner/m8;)V","21f7b105afa4bc886a27dfa6cedbe1c95e5770bdf048437235b219c8cab62b90"),
        Map.entry("Llocal/runner/q;->d()Z","d8ed95e86a5d62205aebe500eb02969c893cb16409677db508ca9f3caeb9824b"),
        Map.entry("Llocal/runner/n3;->b(Ljava/lang/String;Ljava/security/PublicKey;)Ljava/util/Map;","7c0b0c5eecd79dee6451f44bc79bbe73e6cd95a8f5341aa00ab8dac03d35d70f"),
        Map.entry("Llocal/runner/a8;-><init>(Ljava/lang/String;Z)V","d4a2c9773fa9bec5da42e9810482d7236e1499416b7c362daa1eb7d16a809b70"),
        Map.entry("Llocal/runner/PublicUpdateChannel;->sources()[B","64f07db8f0e3b8e33687f238d3918782a59ba75892f06032d149975162169a4c"),
        Map.entry("Llocal/runner/PublicUpdateChannel;->open(Ljava/lang/String;)Ljava/net/HttpURLConnection;","94b383f9e1f7138212156bac797d1fedb53772d4ade03733d38d9a738ff2d0fc"),
        Map.entry("Llocal/runner/PublicUpdateChannel;->socketFactory()Ljavax/net/ssl/SSLSocketFactory;","bb8b42bab87dc3a37095b8535b5e3f083b2711c610e5cb6ab756475b0e7506e9"),
        Map.entry("Llocal/runner/e6;->A()Ljavax/net/ssl/SSLSocketFactory;","43f2e8bf1b52f4198c1a30a46998ff218a97f239ac10121cb05f7a80d8407fd4")
    );
    static final String[][] PROTECTED={
        {HELPER,"install","(Landroid/content/Context;)V"},
        {"Llocal/runner/e8;","j","(Ljava/io/File;Llocal/runner/m8;)V"},
        {"Llocal/runner/q;","d","()Z"},
        {"Llocal/runner/n3;","b","(Ljava/lang/String;Ljava/security/PublicKey;)Ljava/util/Map;"},
        {"Llocal/runner/a8;","<init>","(Ljava/lang/String;Z)V"},
        {"Llocal/runner/PublicUpdateChannel;","sources","()[B"},
        {"Llocal/runner/PublicUpdateChannel;","open","(Ljava/lang/String;)Ljava/net/HttpURLConnection;"},
        {"Llocal/runner/PublicUpdateChannel;","socketFactory","()Ljavax/net/ssl/SSLSocketFactory;"},
        {"Llocal/runner/e6;","A","()Ljavax/net/ssl/SSLSocketFactory;"}
    };
    static void require(boolean ok,String why){if(!ok)throw new IllegalStateException(why);}
    static String sha(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    static String sha(String s)throws Exception{return sha(s.getBytes(StandardCharsets.UTF_8));}
    static List<Method> methods(ClassDef c){
        List<Method> out=new ArrayList<>();
        for(Object m:c.getDirectMethods())out.add((Method)m);
        for(Object m:c.getVirtualMethods())out.add((Method)m);
        return out;
    }
    static Map<String,ClassDef> load(String apk)throws Exception{
        Map<String,ClassDef> out=new HashMap<>();
        try(var z=new ZipFile(apk)){
            var names=z.stream().map(ZipEntry::getName).filter(n->n.matches("classes(?:[2-9]|[1-9][0-9]+)?\\.dex")).toList();
            require(!names.isEmpty(),"No DEX");
            for(String n:names){var dex=new DexBackedDexFile(new Opcodes(26,-1),z.getInputStream(z.getEntry(n)).readAllBytes(),0);
                for(Object o:(List<?>)dex.classSection){ClassDef c=(ClassDef)o;require(out.put(c.getType(),c)==null,"Duplicate DEX class "+c.getType());}
            }
        }return out;
    }
    static Method method(Map<String,ClassDef> cs,String cls,String name,String proto){
        var c=cs.get(cls);require(c!=null,"Missing class "+cls);List<Method> found=new ArrayList<>();
        for(Method m:methods(c))if(m.getName().equals(name)&&proto(m).equals(proto))found.add(m);
        require(found.size()==1,"Nonunique method "+cls+name+proto);return found.get(0);
    }
    static String proto(Method m){StringBuilder b=new StringBuilder("(");for(Object p:m.getParameterTypes())b.append(p);return b.append(')').append(m.getReturnType()).toString();}
    static List<Instruction> ins(Method m){require(m.getImplementation()!=null,"No code "+m);List<Instruction> a=new ArrayList<>();for(Object i:m.getImplementation().getInstructions())a.add((Instruction)i);return a;}
    static String ref(Instruction i){return i instanceof ReferenceInstruction r?r.getReference().toString():"";}
    static Object get(Object object,String name)throws Exception{
        try{return object.getClass().getMethod(name).invoke(object);}catch(NoSuchMethodException e){return null;}
    }
    static String canonical(Method m)throws Exception{
        StringBuilder b=new StringBuilder();b.append(m.getAccessFlags()).append(':').append(m.getImplementation().getRegisterCount()).append('\n');
        for(Instruction i:ins(m)){
            b.append(i.getOpcode().name);
            // Reflect fixed operand getters to handle the bundled dexlib API variants.
            for(String key:List.of("getCodeUnits","getRegisterCount","getRegisterA","getRegisterB","getRegisterC","getRegisterD","getRegisterE","getRegisterF","getRegisterG","getStartRegister","getWideLiteral","getNarrowLiteral","getCodeOffset","getElementWidth")){
                Object value=get(i,key);if(value!=null)b.append(' ').append(key).append('=').append(value);
            }
            if(i instanceof ReferenceInstruction r)b.append(" R=").append(r.getReference());
            if(i instanceof DualReferenceInstruction r)b.append(" R2=").append(r.getReference2());
            if(i instanceof SwitchPayload p)for(Object element:p.getSwitchElements()){SwitchElement e=(SwitchElement)element;b.append(" SWITCH=").append(e.getKey()).append(':').append(e.getOffset());}
            Object array=get(i,"getArrayElements");if(array!=null)b.append(" ARRAY=").append(array);
            b.append('\n');
        }
        for(Object block:m.getImplementation().getTryBlocks()){
            b.append("TRY=").append(get(block,"getStartCodeAddress")).append(':').append(get(block,"getCodeUnitCount"));
            for(Object handler:(Iterable<?>)get(block,"getExceptionHandlers"))b.append(" HANDLER=").append(get(handler,"getExceptionType")).append(':').append(get(handler,"getHandlerCodeAddress"));
            b.append('\n');
        }
        return b.toString();
    }
    static void protectedMethod(Map<String,ClassDef> base,Map<String,ClassDef> next,String[] p)throws Exception{
        String id=p[0]+"->"+p[1]+p[2],value=canonical(method(next,p[0],p[1],p[2])),digest=sha(value);
        if(base!=null)require(value.equals(canonical(method(base,p[0],p[1],p[2]))),"Protected method drift "+id);
        else require(digest.equals(PINNED.get(id)),"Protected method drift "+id);
        System.out.println("PROTECTED_METHOD="+id+" SHA256="+digest);
    }
    static void integrity(String apk,String cert)throws Exception{
        X509Certificate c;
        try(var in=Files.newInputStream(Path.of(cert))){c=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in);}
        require(sha(c.getEncoded()).equals(TRUSTED_CERT),"Untrusted integrity certificate");
        try(var z=new ZipFile(apk)){
            var names=z.stream().map(ZipEntry::getName).toList();require(new HashSet<>(names).size()==names.size(),"Duplicate ZIP entry");
            byte[] contents=z.getInputStream(z.getEntry("META-INF/RUNNER-CONTENTS")).readAllBytes();
            byte[] signature=z.getInputStream(z.getEntry("META-INF/RUNNER-CONTENTS.sig")).readAllBytes();
            Signature verify=Signature.getInstance("SHA256withECDSA");verify.initVerify(c.getPublicKey());verify.update(contents);require(verify.verify(signature),"RUNNER-CONTENTS signature invalid");
            Map<String,String> manifest=new HashMap<>();
            for(String line:new String(contents,StandardCharsets.UTF_8).split("\\n")){
                require(line.matches("[a-f0-9]{64} [^\\r\\n]+"),"Malformed RUNNER-CONTENTS");String name=line.substring(65);
                require(!name.startsWith("META-INF/")&&!name.endsWith("/"),"Invalid contents path "+name);require(manifest.put(name,line.substring(0,64))==null,"Duplicate contents path "+name);
            }
            Set<String> actual=new HashSet<>();for(String name:names)if(!name.startsWith("META-INF/")&&!name.endsWith("/"))actual.add(name);
            require(actual.equals(manifest.keySet()),"RUNNER-CONTENTS does not cover exact non-META files");
            for(String name:actual)require(sha(z.getInputStream(z.getEntry(name)).readAllBytes()).equals(manifest.get(name)),"Contents digest mismatch "+name);
            Map<String,String> raw=Map.of("res/C7.pem","8cec855112f3fd2bb1bbfbc2be21e050d1ae99500f142b236df955c4bb3f34c4","res/Ho.json","624f6ac359d820cbdf947363c54689a0881f542923aaf4e3105ba7ac32226788","res/Hy.json","0da40447ae4084b86e383fe26d23b0358e3f59245dbec74c35b996c975c5f5f5");
            for(var e:raw.entrySet())require(sha(z.getInputStream(z.getEntry(e.getKey())).readAllBytes()).equals(e.getValue()),"Fixed resource drift "+e.getKey());
            System.out.println("INTEGRITY_CERT_SHA256="+sha(c.getEncoded()));System.out.println("RUNNER_CONTENTS_SIGNATURE=PASS");System.out.println("RUNNER_CONTENTS_ENTRIES="+actual.size());System.out.println("RUNNER_CONTENTS_ALL_HASHES=PASS");System.out.println("FIXED_RESOURCES=PASS");
        }
    }
    public static void main(String[]args)throws Exception{
        String candidate=null,baseline=null,cert=null;
        if(args.length==1&&!args[0].startsWith("--"))candidate=args[0];
        else if(args.length==2&&!args[0].startsWith("--")){baseline=args[0];candidate=args[1];}
        else for(int i=0;i<args.length;i+=2){require(i+1<args.length,"Missing argument value");switch(args[i]){case "--candidate":candidate=args[i+1];break;case "--baseline":baseline=args[i+1];break;case "--cert":cert=args[i+1];break;default:throw new IllegalArgumentException("Unknown argument "+args[i]);}}
        require(candidate!=null,"Usage: --candidate APK --cert X509_PEM [--baseline TRUSTED_R4_APK]");
        Map<String,ClassDef> base=null;if(baseline!=null){require(sha(Files.readAllBytes(Path.of(baseline))).equals(TRUSTED_R4),"Untrusted baseline APK");base=load(baseline);}
        var next=load(candidate);var install=method(next,HELPER,"install","(Landroid/content/Context;)V");
        var seq=ins(install);int expiryCount=0;List<String>keys=new ArrayList<>();
        for(int j=0;j<seq.size();j++){
            Instruction i=seq.get(j);String s=ref(i);
            if(s.equals("session_expires_at_ms")||s.equals("credential_expires_at_ms")){
                require(j+2<seq.size(),"Truncated expiry write");require(seq.get(j+1) instanceof WideLiteralInstruction w&&w.getWideLiteral()==4102415999000L,"Wrong expiry "+s);
                require(ref(seq.get(j+2)).equals("Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;"),"Expiry missing putLong "+s);keys.add(s);expiryCount++;
            }
        }
        require(expiryCount==2&&new HashSet<>(keys).size()==2,"Expected both unique expiry writes");
        require(seq.stream().filter(i->ref(i).equals("Ljava/lang/System;->currentTimeMillis()J")).count()==1,"Missing startup timestamp refresh");
        int hookCount=0;boolean located=false;
        for(ClassDef c:next.values())for(Method m:methods(c))if(m.getImplementation()!=null){var is=ins(m);int superAt=-1;
            for(int j=0;j<is.size();j++){
                if(ref(is.get(j)).equals("Landroid/app/Application;->onCreate()V")&&is.get(j).getOpcode().name.equals("invoke-super"))superAt=j;
                if(ref(is.get(j)).equals(INSTALL)){
                    hookCount++;int p0=m.getImplementation().getRegisterCount()-1;
                    boolean operand=is.get(j) instanceof FiveRegisterInstruction r&&r.getRegisterCount()==1&&r.getRegisterC()==p0;
                    located=c.getType().equals("Llocal/runner/RunnerApplication;")&&"Landroid/app/Application;".equals(c.getSuperclass())&&m.getName().equals("onCreate")&&proto(m).equals("()V")&&superAt>=0&&j==superAt+1&&is.get(j).getOpcode().name.equals("invoke-static")&&operand;
                }
            }
        }
        require(hookCount==1&&located,"Expected one p0 startup hook immediately after Application.onCreate");
        for(String[] p:PROTECTED)protectedMethod(base,next,p);
        System.out.println("SESSION_EXPIRES_AT_MS=4102415999000");System.out.println("CREDENTIAL_EXPIRES_AT_MS=4102415999000");System.out.println("LOCAL_EXPIRY=2099-12-31T23:59:59+08:00");System.out.println("STARTUP_HOOK_COUNT="+hookCount);System.out.println("STABLE_ROUTE=https://1810173141-web.github.io/a01-updates/stable/check");System.out.println("FINAL_DEX_EXPIRY_GATE=PASS");
        if(cert!=null)integrity(candidate,cert);else System.out.println("RUNNER_CONTENTS=NOT_REQUESTED");
        System.out.println("LIMIT=Startup local state only; server refresh may overwrite local fields");
    }
}
