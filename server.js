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
const PRESENCE_TTL = 90 * 1000;
const APP_VERSION = '2.0 Pro';
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]');
if (!fs.existsSync(BANS_FILE)) fs.writeFileSync(BANS_FILE, '{}');
function readBans(){try{return JSON.parse(fs.readFileSync(BANS_FILE,'utf8'))}catch{return {}}}
function writeBans(v){fs.writeFileSync(BANS_FILE,JSON.stringify(v,null,2))}
function cleanId(v){return String(v||'').trim().slice(0,100)}
const sessions = new Map();
const COOKIE = 'nx_session';
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
function readNotices(){ try { return JSON.parse(fs.readFileSync(DATA_FILE,'utf8')); } catch { return []; } }
function writeNotices(v){ fs.writeFileSync(DATA_FILE, JSON.stringify(v,null,2)); }
function parseCookies(req){ return Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim()).filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i),decodeURIComponent(x.slice(i+1))]})); }
function session(req){ const token=parseCookies(req)[COOKIE]; const s=token&&sessions.get(token); if(!s||s.expires<Date.now()){if(token)sessions.delete(token);return null;} s.expires=Date.now()+SESSION_TTL;return s; }
function send(res,status,obj,headers={}){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...headers});res.end(JSON.stringify(obj));}
function body(req){return new Promise((resolve,reject)=>{let b='';req.on('data',c=>{b+=c;if(b.length>100000)reject(new Error('请求体过大'))});req.on('end',()=>{try{resolve(JSON.parse(b||'{}'))}catch{reject(new Error('JSON 格式错误'))}});req.on('error',reject)});}
function requireAdmin(req,res){const s=session(req);if(!s||s.role!=='admin'){send(res,401,{error:'需要管理员登录'});return false;}return true;}
const server=http.createServer(async(req,res)=>{
 try{
  const started=Date.now();
  const url=new URL(req.url,'http://localhost');
  if(req.method==='GET'&&url.pathname==='/api/health'){send(res,200,{status:'ok',version:APP_VERSION,latency:Date.now()-started,node:process.version,uptime:Math.round(process.uptime())});return;}
  if(req.method==='POST'&&url.pathname==='/api/login'){
   const data=await body(req); const given=String(data.id||'');
   const a=Buffer.from(given),b=Buffer.from(ADMIN_ID);
   const ok=a.length===b.length&&crypto.timingSafeEqual(a,b);
   const userId=cleanId(given);const bans=readBans();if(!ok&&bans[userId]){send(res,403,{error:'此访问 ID 已被管理员封禁'});return;}const token=crypto.randomBytes(32).toString('hex');const role=ok?'admin':'guest';sessions.set(token,{role,userId,createdAt:Date.now(),lastSeen:Date.now(),expires:Date.now()+SESSION_TTL});
   const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
   send(res,200,{authenticated:true,role},{'Set-Cookie':`${COOKIE}=${token}; HttpOnly; SameSite=None${secure}; Path=/; Max-Age=${SESSION_TTL}`});return;
  }
  if(req.method==='GET'&&url.pathname==='/api/session'){const s=session(req);send(res,200,{authenticated:!!s,role:s?.role||'guest',userId:s?.userId||''});return;}
  if(req.method==='POST'&&url.pathname==='/api/presence'){const s=session(req);if(!s){send(res,401,{error:'未登录'});return;}s.lastSeen=Date.now();send(res,200,{ok:true});return;}
  if(req.method==='GET'&&url.pathname==='/api/admin/users'){if(!requireAdmin(req,res))return;const now=Date.now();const users=[];for(const [token,u] of sessions){if(u.role==='guest'&&u.expires>now&&now-u.lastSeen<PRESENCE_TTL)users.push({id:u.userId,online:true,lastSeen:u.lastSeen,sessionCount:1});}const grouped={};for(const u of users){if(!grouped[u.id])grouped[u.id]=u;else grouped[u.id].sessionCount++;}send(res,200,{users:Object.values(grouped),bans:readBans()});return;}
  if(req.method==='POST'&&url.pathname==='/api/admin/ban'){if(!requireAdmin(req,res))return;const d=await body(req);const id=cleanId(d.id);if(!id){send(res,400,{error:'缺少用户 ID'});return;}const bans=readBans();bans[id]={reason:String(d.reason||'管理员封禁').slice(0,300),at:new Date().toISOString()};writeBans(bans);for(const [token,u] of sessions){if(u.role==='guest'&&u.userId===id)sessions.delete(token);}send(res,200,{ok:true});return;}
  if(req.method==='POST'&&url.pathname==='/api/admin/unban'){if(!requireAdmin(req,res))return;const d=await body(req);const id=cleanId(d.id);const bans=readBans();delete bans[id];writeBans(bans);send(res,200,{ok:true});return;}
  if(req.method==='POST'&&url.pathname==='/api/logout'){const token=parseCookies(req)[COOKIE];if(token)sessions.delete(token);send(res,200,{ok:true},{'Set-Cookie':`${COOKIE}=; HttpOnly; SameSite=None; Path=/; Max-Age=0`});return;}
  if(req.method==='GET'&&url.pathname==='/api/notices'){send(res,200,{notices:readNotices()});return;}
  if(req.method==='POST'&&url.pathname==='/api/admin/notices'){
   if(!requireAdmin(req,res))return;const d=await body(req);const title=String(d.title||'').trim(),content=String(d.content||'').trim();if(!title||!content){send(res,400,{error:'标题和内容不能为空'});return;}if(title.length>160||content.length>10000){send(res,400,{error:'公告内容过长'});return;}
   const list=readNotices();const item={id:crypto.randomUUID(),title,content,createdAt:new Date().toISOString()};list.unshift(item);writeNotices(list.slice(0,100));send(res,201,{notice:item});return;
  }
  if(req.method==='DELETE'&&url.pathname.startsWith('/api/admin/notices/')){if(!requireAdmin(req,res))return;const id=decodeURIComponent(url.pathname.split('/').pop());const list=readNotices();writeNotices(list.filter(n=>n.id!==id));send(res,200,{ok:true});return;}
  if(url.pathname.startsWith('/api/')){send(res,404,{error:'接口不存在'});return;}
  let pathname=decodeURIComponent(url.pathname);if(pathname==='/')pathname='/index.html';const file=path.resolve(ROOT,'.'+pathname);if(!file.startsWith(ROOT+path.sep)){send(res,403,{error:'禁止访问'});return;}
  fs.readFile(file,(err,data)=>{if(err){res.writeHead(404);res.end('Not found');return;}const ext=path.extname(file);const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml'};res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','X-Content-Type-Options':'nosniff','Cache-Control':ext==='.html'?'no-cache':'public, max-age=3600'});res.end(data);});
 }catch(e){send(res,400,{error:e.message||'请求失败'});}
});
server.listen(PORT,'0.0.0.0',()=>console.log(`念绪 AI backend listening on ${PORT}`));
