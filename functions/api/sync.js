/* ===== Penggabungan data (dipakai identik di server & browser) ===== */
function mergeStates(a,b){
  function norm(s){
    s=(s&&typeof s==='object')?s:{};
    return {
      hafalan:Array.isArray(s.hafalan)?s.hafalan:[],
      murajaah:Array.isArray(s.murajaah)?s.murajaah:[],
      cycles:Array.isArray(s.cycles)?s.cycles:[],
      tomb:(s.tomb&&typeof s.tomb==='object')?s.tomb:{},
      resetAt:+s.resetAt||0,
      sAt:(s.sAt&&typeof s.sAt==='object')?s.sAt:{},
      target:s.target===undefined?null:s.target,
      activeCycleId:s.activeCycleId===undefined?null:s.activeCycleId,
      onboardingDismissed:!!s.onboardingDismissed
    };
  }
  a=norm(a); b=norm(b);
  var resetAt=Math.max(a.resetAt,b.resetAt);
  var tomb={};
  // tombstone yang lebih lama dari reset/pemulihan tidak berlaku lagi
  [a.tomb,b.tomb].forEach(function(t){ for(var k in t){ var v=+t[k]||0; if(v>=resetAt) tomb[k]=Math.max(tomb[k]||0,v); } });
  var out={version:1,resetAt:resetAt,tomb:tomb,sAt:{}};
  ['hafalan','murajaah','cycles'].forEach(function(col){
    var m={};
    [a[col],b[col]].forEach(function(arr){
      arr.forEach(function(it){
        if(!it||!it.id) return;
        var st=it.updatedAt||it.createdAt||0;
        if(tomb[it.id]||st<resetAt) return;
        var prev=m[it.id];
        if(!prev||st>(prev.updatedAt||prev.createdAt||0)) m[it.id]=it;
      });
    });
    out[col]=Object.keys(m).map(function(k){return m[k];});
  });
  ['target','activeCycleId','onboardingDismissed'].forEach(function(f){
    var ta=a.sAt[f]||0, tb=b.sAt[f]||0;
    function emp(v){ return v===null||v===undefined||v===false; }
    var pick=(tb>ta)?b:((tb===ta&&emp(a[f])&&!emp(b[f]))?b:a);
    out[f]=pick[f]; out.sAt[f]=Math.max(ta,tb);
  });
  // siklus aktif harus menunjuk siklus yang masih ada
  if(out.activeCycleId && !out.cycles.some(function(c){return c.id===out.activeCycleId;})) out.activeCycleId=null;
  return out;
}

/* Jejak Hafalan — API sinkronisasi (Cloudflare Pages Function + KV "HAFALAN_KV") */
const MAX_BODY=3*1024*1024;
const TOKEN_TTL=60*60*24*365;
const PBKDF2_ITER=10000;

function json(obj,status){
  return new Response(JSON.stringify(obj),{status:status||200,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
}
function toHex(buf){ return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join(''); }
function fromHex(h){ const a=new Uint8Array(h.length/2); for(let i=0;i<a.length;i++) a[i]=parseInt(h.substr(i*2,2),16); return a; }
async function sha256Hex(str){ return toHex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(str))); }
async function hashPass(pass,saltHex){
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(pass),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:fromHex(saltHex),iterations:PBKDF2_ITER},key,256);
  return toHex(bits);
}
function safeEqual(a,b){ if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length) return false; let r=0; for(let i=0;i<a.length;i++) r|=a.charCodeAt(i)^b.charCodeAt(i); return r===0; }
async function newToken(kv){
  const t=toHex(crypto.getRandomValues(new Uint8Array(32)));
  await kv.put('tok:'+await sha256Hex(t),'1',{expirationTtl:TOKEN_TTL});
  return t;
}
async function authed(request,kv){
  const h=request.headers.get('authorization')||'';
  const m=/^Bearer ([0-9a-f]{64})$/.exec(h); if(!m) return false;
  return (await kv.get('tok:'+await sha256Hex(m[1])))!==null;
}
async function readBody(request){
  const len=+request.headers.get('content-length')||0;
  if(len>MAX_BODY) return {err:'Data terlalu besar'};
  const txt=await request.text();
  if(txt.length>MAX_BODY) return {err:'Data terlalu besar'};
  try{ return {body:JSON.parse(txt)}; }catch(e){ return {err:'Format tidak valid'}; }
}

export async function onRequest(context){
  const {request,env}=context;
  const kv=env.HAFALAN_KV;
  if(!kv) return json({error:'KV belum terpasang'},500);

  // hanya dari situs ini sendiri
  const origin=request.headers.get('origin');
  if(origin && origin!==new URL(request.url).origin) return json({error:'Ditolak'},403);

  const method=request.method;

  if(method==='GET'){
    const claimed=(await kv.get('auth'))!==null;
    if(!request.headers.get('authorization')) return json({claimed});
    if(!(await authed(request,kv))) return json({error:'Sesi tidak valid',claimed},401);
    const raw=await kv.get('state');
    return json({claimed:true,state:raw?JSON.parse(raw):null});
  }

  if(method==='POST'){
    const r=await readBody(request); if(r.err) return json({error:r.err},400);
    const {action,pass}=r.body||{};
    if(typeof pass!=='string'||pass.length<8||pass.length>200) return json({error:'Kata sandi minimal 8 karakter'},400);

    if(action==='claim'){
      if((await kv.get('auth'))!==null) return json({error:'Sudah ada kata sandi. Silakan masuk.'},409);
      const salt=toHex(crypto.getRandomValues(new Uint8Array(16)));
      await kv.put('auth',JSON.stringify({salt,hash:await hashPass(pass,salt)}));
      return json({token:await newToken(kv)});
    }
    if(action==='login'){
      const ip=request.headers.get('cf-connecting-ip')||'x';
      const fk='fail:'+ip;
      const fails=+(await kv.get(fk))||0;
      if(fails>=8) return json({error:'Terlalu banyak percobaan. Coba lagi 15 menit lagi.'},429);
      const rec=await kv.get('auth');
      if(!rec) return json({error:'Belum ada kata sandi'},409);
      const {salt,hash}=JSON.parse(rec);
      if(!safeEqual(await hashPass(pass,salt),hash)){
        await kv.put(fk,String(fails+1),{expirationTtl:900});
        return json({error:'Kata sandi salah'},401);
      }
      await kv.delete(fk);
      return json({token:await newToken(kv)});
    }
    return json({error:'Aksi tidak dikenal'},400);
  }

  if(method==='PUT'){
    if(!(await authed(request,kv))) return json({error:'Sesi tidak valid'},401);
    const r=await readBody(request); if(r.err) return json({error:r.err},400);
    const incoming=r.body&&r.body.state;
    if(!incoming||typeof incoming!=='object'||!Array.isArray(incoming.hafalan)||!Array.isArray(incoming.murajaah)) return json({error:'Data tidak valid'},400);
    const raw=await kv.get('state');
    const merged=mergeStates(raw?JSON.parse(raw):null,incoming);
    await kv.put('state',JSON.stringify(merged));
    return json({state:merged});
  }

  return json({error:'Metode tidak didukung'},405);
}
