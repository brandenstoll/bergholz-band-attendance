const json=(data,status=200)=>Response.json(data,{status,headers:{'Cache-Control':'no-store'}});
const sha=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).map(b=>b.toString(16).padStart(2,'0')).join('');
const cookie=(name,req)=>req.headers.get('Cookie')?.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1);
async function current(req,env){const token=cookie('band_session',req);if(!token)return null;return env.DB.prepare('SELECT m.* FROM sessions s JOIN members m ON m.id=s.member_id WHERE s.token_hash=? AND s.expires_at>? AND m.active=1').bind(await sha(token),Date.now()).first()}
export async function onRequest({request,env,params}){
 const path='/'+(params.path||[]).join('/');const method=request.method;
 try{
  if(path==='/events'&&method==='GET'){const events=await env.DB.prepare('SELECT * FROM events ORDER BY event_date,start_time').all();return json({events:events.results})}
  if(path==='/me'&&method==='GET'){const user=await current(request,env);return json({user:user&&{id:user.id,name:user.display_name,email:user.email,role:user.role,section_id:user.section_id}})}
  if(path==='/auth/request'&&method==='POST'){
   const {email}=await request.json();const normalized=String(email||'').trim().toLowerCase();if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized))return json({error:'Valid email required'},400);
   const member=await env.DB.prepare('SELECT id FROM members WHERE email=? AND active=1').bind(normalized).first();
   if(member){const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,'0');await env.DB.prepare('INSERT INTO login_codes(email,code_hash,expires_at,attempts) VALUES(?,?,?,0) ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0').bind(normalized,await sha(code+':'+env.AUTH_SECRET),Date.now()+600000).run();
    if(!env.RESEND_API_KEY||!env.MAIL_FROM)return json({error:'Email delivery is not configured'},503);
    const sent=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:`Bearer ${env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({from:env.MAIL_FROM,to:[normalized],subject:'Bergholz Band sign-in code',text:`Your Bergholz Band sign-in code is ${code}. It expires in 10 minutes.`})});if(!sent.ok)return json({error:'Could not send code'},502);
   }
   return json({ok:true,message:'If your email is approved, a code has been sent.'});
  }
  if(path==='/auth/verify'&&method==='POST'){
   const {email,code}=await request.json();const normalized=String(email||'').trim().toLowerCase();const record=await env.DB.prepare('SELECT * FROM login_codes WHERE email=?').bind(normalized).first();
   if(!record||record.expires_at<Date.now()||record.attempts>=5)return json({error:'Invalid or expired code'},401);
   await env.DB.prepare('UPDATE login_codes SET attempts=attempts+1 WHERE email=?').bind(normalized).run();
   if(await sha(String(code)+':'+env.AUTH_SECRET)!==record.code_hash)return json({error:'Invalid or expired code'},401);
   const member=await env.DB.prepare('SELECT id FROM members WHERE email=? AND active=1').bind(normalized).first();if(!member)return json({error:'Not authorized'},403);
   await env.DB.prepare('DELETE FROM login_codes WHERE email=?').bind(normalized).run();const token=Array.from(crypto.getRandomValues(new Uint8Array(32))).map(x=>x.toString(16).padStart(2,'0')).join('');await env.DB.prepare('INSERT INTO sessions(token_hash,member_id,expires_at) VALUES(?,?,?)').bind(await sha(token),member.id,Date.now()+30*86400000).run();return new Response(JSON.stringify({ok:true}),{headers:{'Content-Type':'application/json','Set-Cookie':`band_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`}})
  }
  if(path==='/auth/logout'&&method==='POST'){const token=cookie('band_session',request);if(token)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(token)).run();return new Response(JSON.stringify({ok:true}),{headers:{'Content-Type':'application/json','Set-Cookie':'band_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'}})}
  const user=await current(request,env);if(!user)return json({error:'Sign in required'},401);
  if(path==='/attendance'&&method==='GET'){const rows=await env.DB.prepare('SELECT a.event_id,a.member_id,a.response,m.display_name,m.section_id FROM attendance a JOIN members m ON m.id=a.member_id WHERE m.active=1 AND (m.id=? OR (? IN (\'leader\',\'admin\') AND (m.section_id=? OR ?=\'admin\')))').bind(user.id,user.role,user.section_id,user.role).all();return json({attendance:rows.results})}
  if(path==='/attendance'&&method==='POST'){const {event_id,response}=await request.json();if(!['yes','no','maybe'].includes(response)||!Number.isInteger(event_id))return json({error:'Invalid response'},400);const event=await env.DB.prepare('SELECT id FROM events WHERE id=? AND status=\'scheduled\'').bind(event_id).first();if(!event)return json({error:'Event unavailable'},404);await env.DB.prepare('INSERT INTO attendance(event_id,member_id,response) VALUES(?,?,?) ON CONFLICT(event_id,member_id) DO UPDATE SET response=excluded.response,updated_at=CURRENT_TIMESTAMP').bind(event_id,user.id,response).run();return json({ok:true})}
  if(path==='/members'&&method==='GET'){if(!['leader','admin'].includes(user.role))return json({error:'Forbidden'},403);const rows=await env.DB.prepare('SELECT id,display_name,email,section_id,role,active FROM members WHERE section_id=? OR ?=\'admin\' ORDER BY display_name').bind(user.section_id,user.role).all();return json({members:rows.results})}
  if(path==='/events'&&method==='POST'){if(!['leader','admin'].includes(user.role))return json({error:'Forbidden'},403);const e=await request.json();if(!['rehearsal','performance'].includes(e.event_type)||!/^\d{4}-\d{2}-\d{2}$/.test(e.event_date)||!e.title)return json({error:'Invalid event'},400);await env.DB.prepare('INSERT INTO events(title,event_type,event_date,start_time,location,notes) VALUES(?,?,?,?,?,?)').bind(e.title,e.event_type,e.event_date,e.start_time||null,e.location||null,e.notes||null).run();return json({ok:true})}
  return json({error:'Not found'},404);
 }catch(e){return json({error:'Request failed'},500)}
}
