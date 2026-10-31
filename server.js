// 念绪 AI secure backend (Node.js 18+, dependency-free)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
const ADMIN_ID = process.env.ADMIN_ID;
if (!ADMIN_ID) { console.error('请设置环境变量 ADMIN_ID（管理员登录凭据）'); process.exit(1); }
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const DATA_FILE = path.join(DATA_DIR, 'notices.json');
const BANS_FILE = path.join(DATA_DIR, 'bans.json');
const AI_CONFIG_FILE = path.join(DATA_DIR, 'ai-config.json');
const PRESENCE_TTL = 90 * 1000;
const APP_VERSION = '2.0 Pro';
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]');
if (!fs.existsSync(BANS_FILE)) fs.writeFileSync(BANS_FILE, '{}');
const DEFAULT_AI_APIS = [
 {name:'Pollinations 公共入口',url:'https://text.pollinations.ai/openai',model:'openai',enabled:true,key:process.env.POLLINATIONS_API_KEY||''},
 {name:'念绪AI',url:'https://open.bigmodel.cn/api/paas/v4/chat/completions',model:'glm-5.3',enabled:false,key:process.env.ZHIPU_API_KEY||''},
 {name:'Groq 免费低延迟层',url:'https://api.groq.com/openai/v1/chat/completions',model:'openai/gpt-oss-20b',enabled:false,key:process.env.GROQ_API_KEY||''},
 {name:'Hugging Face 免费额度',url:'https://router.huggingface.co/v1/chat/completions',model:'openai/gpt-oss-120b:fastest',enabled:false,key:process.env.HF_TOKEN||''},
 {name:'Cerebras Free Trial',url:'https://api.cerebras.ai/v1/chat/completions',model:'gpt-oss-120b',enabled:false,key:process.env.CEREBRAS_API_KEY||''}
];
if (!fs.existsSync(AI_CONFIG_FILE)) fs.writeFileSync(AI_CONFIG_FILE, JSON.stringify(DEFAULT_AI_APIS,null,2));
function readBans(){try{return JSON.parse(fs.readFileSync(BANS_FILE,'utf8'))}catch{return {}}}
function writeBans(v){fs.writeFileSync(BANS_FILE,JSON.stringify(v,null,2))}
function cleanId(v){return String(v||'').trim().slice(0,100)}
const sessions = new Map();
const COOKIE = 'nx_session';
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const BLOCKED_IPS = new Set(String(process.env.BLOCKED_IPS||'').split(',').map(x=>x.trim()).filter(Boolean));
const rateBuckets = new Map();
function clientIp(req){return String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim().slice(0,80)}
function allowed(req,res,kind,limit,windowMs){
 const ip=clientIp(req);if(BLOCKED_IPS.has(ip)){send(res,403,{error:'访问被防火墙拦截'});return false}
 const now=Date.now(),key=kind+':'+ip;let b=rateBuckets.get(key);if(!b||b.until<now)b={count:0,until:now+windowMs};b.count++;rateBuckets.set(key,b);
 if(b.count>limit){const retry=Math.max(1,Math.ceil((b.until-now)/1000));send(res,429,{error:'请求过于频繁，请稍后再试',retryAfter:retry},{'Retry-After':String(retry)});return false}return true;
}
setInterval(()=>{const now=Date.now();for(const [k,v] of rateBuckets)if(v.until<now)rateBuckets.delete(k)},5*60*1000).unref();
function readNotices(){ try { return JSON.parse(fs.readFileSync(DATA_FILE,'utf8')); } catch { return []; } }
function writeNotices(v){ fs.writeFileSync(DATA_FILE, JSON.stringify(v,null,2)); }
function parseCookies(req){ return Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim()).filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i),decodeURIComponent(x.slice(i+1))]})); }
function session(req){ const token=parseCookies(req)[COOKIE]; const s=token&&sessions.get(token); if(!s||s.expires<Date.now()){if(token)sessions.delete(token);return null;} s.expires=Date.now()+SESSION_TTL;return s; }
function send(res,status,obj,headers={}){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin','Permissions-Policy':'camera=(),microphone=(),geolocation=()',...headers});res.end(JSON.stringify(obj));}
function body(req){return new Promise((resolve,reject)=>{let b='';req.on('data',c=>{b+=c;if(b.length>100000)reject(new Error('请求体过大'))});req.on('end',()=>{try{resolve(JSON.parse(b||'{}'))}catch{reject(new Error('JSON 格式错误'))}});req.on('error',reject)});}
function requireAdmin(req,res){const s=session(req);if(!s||s.role!=='admin'){send(res,401,{error:'需要管理员登录'});return false;}return true;}
function readAiApis(){try{const v=JSON.parse(fs.readFileSync(AI_CONFIG_FILE,'utf8'));if(!Array.isArray(v))return DEFAULT_AI_APIS;return v.map((a,i)=>({...a,key:a.key||DEFAULT_AI_APIS[i]?.key||''}))}catch{return DEFAULT_AI_APIS}}
function writeAiApis(v){fs.writeFileSync(AI_CONFIG_FILE,JSON.stringify(v,null,2))}
function publicAiApis(includeKeys=false){return readAiApis().map(a=>includeKeys?{...a,keySet:Boolean(a.key)}:{name:a.name,url:a.url,model:a.model,enabled:a.enabled,keySet:Boolean(a.key)})}
function aiAnswer(data){const answer=data?.choices?.[0]?.message?.content??data?.choices?.[0]?.text??data?.text??data?.result;if(typeof answer==='string'&&answer.trim())return answer.trim();if(Array.isArray(answer)){const s=answer.map(x=>x.text||'').join('');if(s.trim())return s.trim()}throw new Error(data?.error?.message||'无法识别接口返回内容')}
async function proxyAiChat(messages){
 const candidates=readAiApis().filter(a=>a.enabled&&a.url&&a.model);
 if(!candidates.length)throw new Error('管理员尚未启用服务器接口');
 let last;
 for(const api of candidates){
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),18000);
  try{const headers={'Content-Type':'application/json'};if(api.key)headers.Authorization='Bearer '+api.key;const r=await fetch(api.url,{method:'POST',headers,body:JSON.stringify({model:api.model,messages,temperature:.7}),signal:controller.signal});const raw=await r.text();if(!r.ok)throw new Error('HTTP '+r.status+' '+raw.slice(0,160));let data;try{data=JSON.parse(raw)}catch{data={text:raw}}return {answer:aiAnswer(data),used:api.name}}
  catch(e){last=e}
  finally{clearTimeout(timer)}
 }
 throw last||new Error('服务器接口均不可用');
}
const server=http.createServer(async(req,res)=>{
  try{
   const started=Date.now();
   const url=new URL(req.url,'http://localhost');
   const contentLength=Number(req.headers['content-length']||0);if(contentLength>100000){send(res,413,{error:'请求体过大'});return}
   const routeLimit=url.pathname==='/api/login'?['login',12,5*60*1000]:url.pathname==='/api/ai/chat'?['ai',30,5*60*1000]:url.pathname.startsWith('/api/admin')?['admin',60,5*60*1000]:['api',180,5*60*1000];if(!allowed(req,res,...routeLimit))return;
  if(req.method==='GET'&&url.pathname==='/api/health'){send(res,200,{status:'ok',version:APP_VERSION,latency:Date.now()-started,node:process.version,uptime:Math.round(process.uptime())});return;}
  if(req.method==='POST'&&url.pathname==='/api/login'){
   const data=await body(req); const given=String(data.id||'');
   const a=Buffer.from(given),b=Buffer.from(ADMIN_ID);
   const ok=a.length===b.length&&crypto.timingSafeEqual(a,b);
   const userId=cleanId(given);const bans=readBans();if(!ok&&bans[userId]){send(res,403,{error:'此访问 ID 已被管理员封禁'});return;}const token=crypto.randomBytes(32).toString('hex');const role=ok?'admin':'guest';sessions.set(token,{role,userId,createdAt:Date.now(),lastSeen:Date.now(),expires:Date.now()+SESSION_TTL});
   const cookieMode = process.env.NODE_ENV === 'production' ? 'SameSite=None; Secure' : 'SameSite=Lax';
   send(res,200,{authenticated:true,role},{'Set-Cookie':`${COOKIE}=${token}; HttpOnly; ${cookieMode}; Path=/; Max-Age=${SESSION_TTL}`});return;
  }
  if(req.method==='GET'&&url.pathname==='/api/session'){const s=session(req);send(res,200,{authenticated:!!s,role:s?.role||'guest',userId:s?.userId||''});return;}
  if(req.method==='POST'&&url.pathname==='/api/presence'){const s=session(req);if(!s){send(res,401,{error:'未登录'});return;}s.lastSeen=Date.now();send(res,200,{ok:true});return;}
  if(req.method==='GET'&&url.pathname==='/api/admin/apis'){if(!requireAdmin(req,res))return;send(res,200,{apis:publicAiApis(true)});return;}
  if(req.method==='PUT'&&url.pathname==='/api/admin/apis'){
   if(!requireAdmin(req,res))return;const d=await body(req);if(!Array.isArray(d.apis)||d.apis.length<1||d.apis.length>10){send(res,400,{error:'接口配置必须是 1 至 10 项'});return;}
   const old=readAiApis();const next=d.apis.map((a,i)=>{const prev=old[i]||{};return {name:String(a.name||'').slice(0,120),url:String(a.url||'').slice(0,500),model:String(a.model||'').slice(0,160),enabled:Boolean(a.enabled),key:String(a.key||'')||prev.key||''}});writeAiApis(next);send(res,200,{ok:true,apis:publicAiApis()});return;
  }
  if(req.method==='POST'&&url.pathname==='/api/ai/chat'){
   if(!session(req)){send(res,401,{error:'请先登录'});return;}const d=await body(req);if(!Array.isArray(d.messages)||d.messages.length>24){send(res,400,{error:'消息上下文无效'});return;}const result=await proxyAiChat(d.messages);send(res,200,result);return;
  }
  if(req.method==='GET'&&url.pathname==='/api/admin/users'){if(!requireAdmin(req,res))return;const now=Date.now();const users=[];for(const [token,u] of sessions){if(u.role==='guest'&&u.expires>now&&now-u.lastSeen<PRESENCE_TTL)users.push({id:u.userId,online:true,lastSeen:u.lastSeen,sessionCount:1});}const grouped={};for(const u of users){if(!grouped[u.id])grouped[u.id]=u;else grouped[u.id].sessionCount++;}send(res,200,{users:Object.values(grouped),bans:readBans()});return;}
  if(req.method==='POST'&&url.pathname==='/api/admin/ban'){if(!requireAdmin(req,res))return;const d=await body(req);const id=cleanId(d.id);if(!id){send(res,400,{error:'缺少用户 ID'});return;}const bans=readBans();bans[id]={reason:String(d.reason||'管理员封禁').slice(0,300),at:new Date().toISOString()};writeBans(bans);for(const [token,u] of sessions){if(u.role==='guest'&&u.userId===id)sessions.delete(token);}send(res,200,{ok:true});return;}
  if(req.method==='POST'&&url.pathname==='/api/admin/unban'){if(!requireAdmin(req,res))return;const d=await body(req);const id=cleanId(d.id);const bans=readBans();delete bans[id];writeBans(bans);send(res,200,{ok:true});return;}
  if(req.method==='POST'&&url.pathname==='/api/logout'){const token=parseCookies(req)[COOKIE];if(token)sessions.delete(token);const cookieMode=process.env.NODE_ENV==='production'?'SameSite=None; Secure':'SameSite=Lax';send(res,200,{ok:true},{'Set-Cookie':`${COOKIE}=; HttpOnly; ${cookieMode}; Path=/; Max-Age=0`});return;}
  if(req.method==='GET'&&url.pathname==='/api/notices'){send(res,200,{notices:readNotices()});return;}
  if(req.method==='POST'&&url.pathname==='/api/admin/notices'){
   if(!requireAdmin(req,res))return;const d=await body(req);const title=String(d.title||'').trim(),content=String(d.content||'').trim();if(!title||!content){send(res,400,{error:'标题和内容不能为空'});return;}if(title.length>160||content.length>10000){send(res,400,{error:'公告内容过长'});return;}
   const list=readNotices();const item={id:crypto.randomUUID(),title,content,createdAt:new Date().toISOString()};list.unshift(item);writeNotices(list.slice(0,100));send(res,201,{notice:item});return;
  }
  if(req.method==='DELETE'&&url.pathname.startsWith('/api/admin/notices/')){if(!requireAdmin(req,res))return;const id=decodeURIComponent(url.pathname.split('/').pop());const list=readNotices();writeNotices(list.filter(n=>n.id!==id));send(res,200,{ok:true});return;}
  if(url.pathname.startsWith('/api/')){send(res,404,{error:'接口不存在'});return;}
  let pathname=decodeURIComponent(url.pathname);if(pathname==='/')pathname='/index.html';const file=path.resolve(ROOT,'.'+pathname);if(!file.startsWith(ROOT+path.sep)||file.startsWith(path.resolve(DATA_DIR)+path.sep)){send(res,403,{error:'禁止访问'});return;}
  fs.readFile(file,(err,data)=>{if(err){res.writeHead(404,{'X-Content-Type-Options':'nosniff'});res.end('Not found');return;}const ext=path.extname(file);const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml'};res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin','Permissions-Policy':'camera=(),microphone=(),geolocation=()','Cache-Control':ext==='.html'?'no-cache':'public, max-age=3600'});res.end(data);});
 }catch(e){send(res,400,{error:e.message||'请求失败'});}
});
server.listen(PORT,'0.0.0.0',()=>console.log(`念绪 AI backend listening on ${PORT}`));
