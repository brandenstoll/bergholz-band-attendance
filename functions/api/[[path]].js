const json=(data,status=200)=>Response.json(data,{status,headers:{'Cache-Control':'no-store'}});
const sha=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).map(b=>b.toString(16).padStart(2,'0')).join('');
const cookie=(name,req)=>req.headers.get('Cookie')?.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1);
const goodDate=s=>/^\d{4}-\d{2}-\d{2}$/.test(s)&&!Number.isNaN(Date.parse(s+'T12:00:00Z'))&&new Date(s+'T12:00:00Z').toISOString().slice(0,10)===s;
const goodTime=s=>s===null||s===''||/^([01]\d|2[0-3]):[0-5]\d$/.test(s);
const emailOK=s=>/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);
const owner=u=>u?.email?.toLowerCase()==='brandenstoll@gmail.com';
const admin=u=>u&&(owner(u)||u.role==='admin');
const leader=u=>u&&(admin(u)||u.role==='leader');
async function current(req,env){const token=cookie('band_session',req);if(!token)return null;return env.DB.prepare('SELECT m.* FROM sessions s JOIN members m ON m.id=s.member_id WHERE s.token_hash=? AND s.expires_at>? AND m.active=1').bind(await sha(token),Date.now()).first()}
async function body(req){try{return await req.json()}catch{return null}}
export async function onRequest({request,env,params}){
 const path='/'+(Array.isArray(params.path)?params.path:[params.path].filter(Boolean)).join('/');const method=request.method;
 try{
  if(!env.DB)return json({error:'Database binding unavailable'},503);
  if(!['GET','HEAD'].includes(method)){const origin=request.headers.get('Origin');if(origin&&origin!==new URL(request.url).origin)return json({error:'Invalid request origin'},403)}
  if(path==='/events'&&method==='GET'){const rows=await env.DB.prepare('SELECT * FROM events ORDER BY event_date,start_time,id').all();return json({events:rows.results})}
  if(path==='/me'&&method==='GET'){const u=await current(request,env);return json({user:u&&{id:u.id,name:u.display_name,email:u.email,role:owner(u)?'owner':u.role,section_id:u.section_id,section_confirmed:u.section_confirmed!==0}})}
  if(path==='/auth/request'&&method==='POST'){
   const data=await body(request);const normalized=String(data?.email||'').trim().toLowerCase();if(!emailOK(normalized))return json({error:'Valid email required'},400);
   const member=await env.DB.prepare('SELECT id FROM members WHERE email=? AND active=1').bind(normalized).first();
   if(member){if(!env.AUTH_SECRET||!env.RESEND_API_KEY||!env.MAIL_FROM)return json({error:'Email login is not configured'},503);
    const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,'0');
    await env.DB.prepare('INSERT INTO login_codes(email,code_hash,expires_at,attempts) VALUES(?,?,?,0) ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0').bind(normalized,await sha(code+':'+env.AUTH_SECRET),Date.now()+600000).run();
    const sent=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:`Bearer ${env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({from:env.MAIL_FROM,to:[normalized],subject:'Bergholz Band sign-in code',text:`Your Bergholz Band sign-in code is ${code}. It expires in 10 minutes.`})});if(!sent.ok)return json({error:'Could not send code. Check your verified Resend sending domain and recipient.'},502);
   }return json({ok:true,message:'If your email is approved, a code has been sent.'});
  }
  if(path==='/auth/verify'&&method==='POST'){
   const data=await body(request);const normalized=String(data?.email||'').trim().toLowerCase();const record=await env.DB.prepare('SELECT * FROM login_codes WHERE email=?').bind(normalized).first();
   if(!record||record.expires_at<Date.now()||record.attempts>=5)return json({error:'Invalid or expired code'},401);
   await env.DB.prepare('UPDATE login_codes SET attempts=attempts+1 WHERE email=?').bind(normalized).run();
   if(!env.AUTH_SECRET||await sha(String(data?.code||'')+':'+env.AUTH_SECRET)!==record.code_hash)return json({error:'Invalid or expired code'},401);
   const member=await env.DB.prepare('SELECT id FROM members WHERE email=? AND active=1').bind(normalized).first();if(!member)return json({error:'Not authorized'},403);
   await env.DB.prepare('DELETE FROM login_codes WHERE email=?').bind(normalized).run();const token=Array.from(crypto.getRandomValues(new Uint8Array(32))).map(x=>x.toString(16).padStart(2,'0')).join('');
   await env.DB.prepare('INSERT INTO sessions(token_hash,member_id,expires_at) VALUES(?,?,?)').bind(await sha(token),member.id,Date.now()+30*86400000).run();
   return new Response(JSON.stringify({ok:true}),{headers:{'Content-Type':'application/json','Cache-Control':'no-store','Set-Cookie':`band_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`}})
  }
  if(path==='/auth/logout'&&method==='POST'){const token=cookie('band_session',request);if(token)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(token)).run();return new Response(JSON.stringify({ok:true}),{headers:{'Content-Type':'application/json','Set-Cookie':'band_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'}})}
  const user=await current(request,env);if(!user)return json({error:'Sign in required'},401);
  if(path==='/documents' && method==='GET'){
  const rows=await env.DB.prepare(`
    SELECT id,event_id,title,filename,
           content_type,file_size,uploaded_at
    FROM event_documents
    ORDER BY uploaded_at DESC,id DESC
  `).all();

  return json({documents:rows.results});
}
  if(path==='/documents' && method==='POST'){
  if(!['admin','owner'].includes(user.role)){
    return json({error:'Administrator access required'},403);
  }

  const form=await request.formData();
  const event_id=Number(form.get('event_id'));
  const title=String(form.get('title')||'').trim();
  const file=form.get('file');

  if(!Number.isSafeInteger(event_id)||event_id<1){
    return json({error:'Select a valid event'},400);
  }

  if(!title||title.length>150){
    return json({error:'Enter a valid document title'},400);
  }

  if(!(file instanceof File)||file.size===0){
    return json({error:'Select a file'},400);
  }

  if(file.size>10*1024*1024){
    return json({error:'Maximum file size is 10 MB'},400);
  }

  const allowed={
    pdf:'application/pdf',
    doc:'application/msword',
    docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls:'application/vnd.ms-excel',
    xlsx:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    txt:'text/plain'
  };

  const ext=file.name.split('.').pop().toLowerCase();
  const content_type=allowed[ext];

  if(!content_type){
    return json({error:'Unsupported file type'},400);
  }

  const event=await env.DB.prepare(
    'SELECT id FROM events WHERE id=?'
  ).bind(event_id).first();

  if(!event){
    return json({error:'Event not found'},404);
  }

  const object_key=`events/${event_id}/${crypto.randomUUID()}.${ext}`;

  await env.DOCUMENTS.put(object_key,file.stream(),{
    httpMetadata:{contentType:content_type}
  });

  try{
    await env.DB.prepare(`
      INSERT INTO event_documents
      (event_id,title,filename,object_key,
       content_type,file_size,uploaded_by)
      VALUES (?,?,?,?,?,?,?)
    `).bind(
      event_id,title,file.name,object_key,
      content_type,file.size,user.id
    ).run();
  }catch(e){
    await env.DOCUMENTS.delete(object_key);
    throw e;
  }

  return json({ok:true});
}
  if(path.startsWith('/documents/') && method==='GET'){
  const id=Number(path.split('/')[2]);

  if(!Number.isSafeInteger(id)||id<1){
    return json({error:'Invalid document ID'},400);
  }

  const doc=await env.DB.prepare(
    'SELECT * FROM event_documents WHERE id=?'
  ).bind(id).first();

  if(!doc){
    return json({error:'Document not found'},404);
  }

  const object=await env.DOCUMENTS.get(doc.object_key);

  if(!object){
    return json({error:'File not found'},404);
  }

  const filename=encodeURIComponent(doc.filename)
    .replace(/['()*]/g,c=>'%'+c.charCodeAt(0).toString(16));

  return new Response(object.body,{
    headers:{
      'Content-Type':doc.content_type,
      'Content-Disposition':`attachment; filename*=UTF-8''${filename}`,
      'Content-Length':String(object.size),
      'Cache-Control':'private, no-store',
      'X-Content-Type-Options':'nosniff'
    }
  });
}
  if(path.startsWith('/documents/') && method==='DELETE'){
  if(!['admin','owner'].includes(user.role)){
    return json({error:'Administrator access required'},403);
  }

  const id=Number(path.split('/')[2]);

  if(!Number.isSafeInteger(id)||id<1){
    return json({error:'Invalid document ID'},400);
  }

  const doc=await env.DB.prepare(
    'SELECT * FROM event_documents WHERE id=?'
  ).bind(id).first();

  if(!doc){
    return json({error:'Document not found'},404);
  }

  await env.DOCUMENTS.delete(doc.object_key);

  await env.DB.prepare(
    'DELETE FROM event_documents WHERE id=?'
  ).bind(id).run();

  return json({ok:true});
}
   if(path==='/me/section'&&method==='POST'){
  const d=await body(request);
  const section=Number(d?.section_id);
  const name=String(d?.display_name??'').trim();

  if(!name||name.length>100)
    return json({error:'Enter your full name'},400);

  if(!Number.isSafeInteger(section)||section<1)
    return json({error:'Choose a valid section'},400);

  const found=await env.DB.prepare(
    'SELECT id FROM sections WHERE id=?'
  ).bind(section).first();

  if(!found)
    return json({error:'Section not found'},404);

  if(user.section_confirmed!==0)
    return json({
      error:'Your profile is already confirmed. Contact an administrator to change it.'
    },403);

  await env.DB.prepare(
    'UPDATE members SET display_name=?,section_id=?,section_confirmed=1 WHERE id=? AND section_confirmed=0'
  ).bind(name,section,user.id).run();

  return json({ok:true});
}
   if(path==='/sections'&&method==='GET'){const rows=await env.DB.prepare('SELECT id,name FROM sections ORDER BY name').all();return json({sections:rows.results})}
  if(path==='/attendance'&&method==='GET'){
   const rows=await env.DB.prepare('SELECT a.event_id,a.member_id,a.response,m.display_name,m.section_id FROM attendance a JOIN members m ON m.id=a.member_id WHERE m.active=1 AND m.section_confirmed=1 AND (m.id=? OR (?=1 AND (m.section_id=? OR ?=1)))').bind(user.id,leader(user)?1:0,user.section_id,admin(user)?1:0).all();return json({attendance:rows.results})
  }
  if(path==='/attendance'&&method==='POST'){
    if(user.section_confirmed===0)return json({error:'Select your section before recording attendance'},403);
    const d=await body(request);if(!['yes','no','maybe'].includes(d?.response)||!Number.isInteger(d?.event_id))return json({error:'Invalid response'},400);
   const event=await env.DB.prepare("SELECT id FROM events WHERE id=? AND status='scheduled'").bind(d.event_id).first();if(!event)return json({error:'Event unavailable'},404);
   const targetId=d.member_id===undefined?user.id:Number(d.member_id);
   if(!Number.isSafeInteger(targetId)||targetId<1)return json({error:'Invalid member'},400);
   if(targetId!==user.id){
    if(!leader(user))return json({error:'Forbidden'},403);
    const target=await env.DB.prepare('SELECT section_id FROM members WHERE id=? AND active=1 AND section_confirmed=1').bind(targetId).first();
    if(!target||(!admin(user)&&(!user.section_id||target.section_id!==user.section_id)))return json({error:'Forbidden'},403);
   }
   await env.DB.prepare('INSERT INTO attendance(event_id,member_id,response) VALUES(?,?,?) ON CONFLICT(event_id,member_id) DO UPDATE SET response=excluded.response,updated_at=CURRENT_TIMESTAMP').bind(d.event_id,targetId,d.response).run();return json({ok:true})
  }
  if(path==='/attendance/verification'&&method==='GET'){
  if(!user)return json({error:'Unauthorized'},401);
  if(!leader(user))return json({error:'Forbidden'},403);

  const rows=await env.DB.prepare(`
    SELECT v.event_id,v.member_id,v.status,
           v.verified_by,v.verified_at,
           m.display_name,m.section_id
    FROM attendance_verification v
    JOIN members m ON m.id=v.member_id
    WHERE m.active=1
      AND (?=1 OR m.section_id=?)
    ORDER BY v.event_id,m.display_name
  `).bind(admin(user)?1:0,user.section_id).all();

  return json({verifications:rows.results});
}

if(path==='/attendance/verification'&&method==='POST'){
  if(!user)return json({error:'Unauthorized'},401);
  if(!leader(user))return json({error:'Forbidden'},403);

  const d=await body(request);
  const eventId=Number(d?.event_id);
  const memberId=Number(d?.member_id);
  const status=d?.status;

  if(!Number.isSafeInteger(eventId)||eventId<1||
     !Number.isSafeInteger(memberId)||memberId<1||
     !['present','no_show','unverified'].includes(status)){
    return json({error:'Invalid verification'},400);
  }

  const event=await env.DB.prepare(
    'SELECT id FROM events WHERE id=?'
  ).bind(eventId).first();

  if(!event)return json({error:'Event not found'},404);

  const member=await env.DB.prepare(`
    SELECT id,section_id
    FROM members
    WHERE id=? AND active=1
  `).bind(memberId).first();

  if(!member)return json({error:'Member not found'},404);

  if(!admin(user)&&
     (!user.section_id||member.section_id!==user.section_id)){
    return json({error:'Forbidden'},403);
  }

  if (status === 'unverified') {
    await env.DB.prepare(`
      DELETE FROM attendance_verification
      WHERE event_id=? AND member_id=?
    `).bind(eventId,memberId).run();

    return json({ok:true});
  }

  await env.DB.prepare(`
    INSERT INTO attendance_verification
      (event_id,member_id,status,verified_by)
    VALUES (?,?,?,?)
    ON CONFLICT(event_id,member_id)
    DO UPDATE SET
      status=excluded.status,
      verified_by=excluded.verified_by,
      verified_at=CURRENT_TIMESTAMP
  `).bind(eventId,memberId,status,user.id).run();

  return json({ok:true});
}
  if(path==='/members'&&method==='GET'){
   if(!user)return json({error:'Unauthorized'},401);
   
const rows = await env.DB.prepare(
  `SELECT m.id, m.display_name, m.email,
          m.section_id,
CASE
  WHEN m.section_confirmed = 1
  THEN s.name
  ELSE 'Not Selected'
END AS section_name,
          m.section_confirmed, m.role, m.active
   FROM members m
   LEFT JOIN sections s ON s.id = m.section_id
   WHERE m.active = 1
   ORDER BY m.display_name`
).all();
return json({members: rows.results});

  }
   if(path==='/members/bulk'&&method==='POST'){
    if(!admin(user))return json({error:'Forbidden'},403);
    const d=await body(request);
    if(!Array.isArray(d?.members)||d.members.length<1||d.members.length>100)return json({error:'Provide between 1 and 100 members'},400);
    const section=Number(user.section_id);
    if(!Number.isInteger(section)||section<1)return json({error:'Your account has no valid section'},400);
    const sec=await env.DB.prepare('SELECT id FROM sections WHERE id=?').bind(section).first();
    if(!sec)return json({error:'Section not found'},404);
    const cleaned=[],seen=new Set();
    for(let i=0;i<d.members.length;i++){
     const m = d.members[i];
const email = String(m?.email || '').trim().toLowerCase();
const name = String(m?.display_name || '').trim() || email.split('@')[0];

if (!emailOK(email) || !name || name.length > 100)
  return json({error: `Invalid name or email on entry ${i+1}; nothing was imported`}, 400);

     if(seen.has(email))return json({error:`Duplicate email on entry ${i+1}; nothing was imported`},400);
     seen.add(email);cleaned.push({name,email});
    }
    let added=0,skipped=0;const errors=[];
    for(const m of cleaned){
     try{
      const result=await env.DB.prepare("INSERT OR IGNORE INTO members(email,display_name,section_id,role,active,section_confirmed) VALUES(?,?,?,'member',1,0)").bind(m.email,m.name,section).run();
      if(result.meta?.changes===1)added++;else skipped++;
     }catch(e){console.error('Bulk member insert failed',e?.message||e);errors.push(`Could not add ${m.email}`)}
    }
    return json({ok:errors.length===0,added,skipped,errors});
   }
  if(path==='/members'&&method==='POST'){
   if(!admin(user))return json({error:'Forbidden'},403);const d=await body(request);const email=String(d?.email||'').trim().toLowerCase(),name=String(d?.display_name||'').trim();const section=Number(d?.section_id);
   if(!emailOK(email)||!name||name.length>100||!Number.isInteger(section)||section<1)return json({error:'Valid name, email and section required'},400);
   if(!admin(user)&&section!==user.section_id)return json({error:'Cannot add members to another section'},403);
   const sec=await env.DB.prepare('SELECT id FROM sections WHERE id=?').bind(section).first();if(!sec)return json({error:'Section not found'},404);
   const role=d?.role==='admin'&&owner(user)?'admin':d?.role==='leader'?'leader':'member';if(!admin(user)&&role==='leader')return json({error:'Only band admins can appoint section leaders'},403);
   try{await env.DB.prepare('INSERT INTO members(email,display_name,section_id,role,active) VALUES(?,?,?,?,1)').bind(email,name,section,role).run()}catch{return json({error:'That email address is already registered'},409)}return json({ok:true},201)
  }
  const memberMatch=path.match(/^\/members\/(\d+)$/);
  if(memberMatch&&method==='PATCH'){
   if(!admin(user))return json({error:'Forbidden'},403);const id=Number(memberMatch[1]);const target=await env.DB.prepare('SELECT * FROM members WHERE id=?').bind(id).first();if(!target)return json({error:'Member not found'},404);
   if(!owner(user)&&(owner(target)||target.role==='admin'))return json({error:'Only the owner can edit administrators'},403);
   if(!admin(user)&&target.section_id!==user.section_id)return json({error:'Forbidden'},403);
   const d=await body(request);const name=String(d?.display_name??target.display_name).trim();const email=String(d?.email??target.email).trim().toLowerCase();const active=d?.active===undefined?target.active:Number(d.active);const role=d?.role??target.role;const section=d?.section_id===undefined?target.section_id:Number(d.section_id);
   if(owner(target)&&(email!==target.email||!active||role!==target.role))return json({error:'Cannot change owner access'},403);
   if(!name||name.length>100||!emailOK(email)||![0,1].includes(active)||!['member','leader','admin'].includes(role)||!Number.isInteger(section))return json({error:'Invalid member details'},400);
   if(!admin(user)&&(role!==target.role||section!==target.section_id))return json({error:'Only band admins can change roles or sections'},403);
   if(!owner(user)&&role==='admin'&&target.role!=='admin')return json({error:'Additional band administrators must be provisioned separately'},403);
   if(id===user.id&&(!active||role!==user.role||section!==user.section_id))return json({error:'You cannot deactivate or change your own access'},400);
   const sec=await env.DB.prepare('SELECT id FROM sections WHERE id=?').bind(section).first();if(!sec)return json({error:'Section not found'},404);
   try{await env.DB.prepare('UPDATE members SET display_name=?,email=?,active=?,role=?,section_id=?,section_confirmed=1 WHERE id=?').bind(name,email,active,role,section,id).run()}catch{return json({error:'Email already in use'},409)}
   if(!active)await env.DB.prepare('DELETE FROM sessions WHERE member_id=?').bind(id).run();return json({ok:true})
  }
  if(path==='/events'&&method==='POST'){
   if(!admin(user))return json({error:'Forbidden'},403);const e=await body(request);if(!['rehearsal','performance'].includes(e?.event_type)||!goodDate(e?.event_date)||!String(e?.title||'').trim()||String(e.title).length>150||!goodTime(e.start_time??null))return json({error:'Invalid event details'},400);
   await env.DB.prepare('INSERT INTO events(title,event_type,event_date,start_time,location,notes) VALUES(?,?,?,?,?,?)').bind(e.title.trim(),e.event_type,e.event_date,e.start_time||null,String(e.location||'').trim()||null,String(e.notes||'').trim()||null).run();return json({ok:true},201)
  }
  const eventMatch=path.match(/^\/events\/(\d+)$/);
  if(eventMatch&&method==='PATCH'){
   if(!admin(user))return json({error:'Forbidden'},403);const id=Number(eventMatch[1]);const old=await env.DB.prepare('SELECT * FROM events WHERE id=?').bind(id).first();if(!old)return json({error:'Event not found'},404);
   const d=await body(request);const e={...old,...d};if(!['rehearsal','performance'].includes(e.event_type)||!goodDate(e.event_date)||!String(e.title||'').trim()||String(e.title).length>150||!goodTime(e.start_time??null)||!['scheduled','cancelled'].includes(e.status))return json({error:'Invalid event details'},400);
   await env.DB.prepare('UPDATE events SET title=?,event_type=?,event_date=?,start_time=?,location=?,notes=?,status=? WHERE id=?').bind(e.title.trim(),e.event_type,e.event_date,e.start_time||null,String(e.location||'').trim()||null,String(e.notes||'').trim()||null,e.status,id).run();return json({ok:true})
  }if(eventMatch && method === 'DELETE'){
  if(!owner(user)){
    return json({error:'Owner access required'},403);
  }

  const id = Number(eventMatch[1]);

  const event = await env.DB.prepare(
    'SELECT id,status FROM events WHERE id=?'
  ).bind(id).first();

  if(!event){
    return json({error:'Event not found'},404);
  }

  if(event.status !== 'cancelled'){
    return json({error:'Only cancelled events can be deleted'},400);
  }

  const results = await env.DB.batch([
  env.DB.prepare(
    "DELETE FROM attendance_verification WHERE event_id=? AND EXISTS (SELECT 1 FROM events WHERE id=? AND status='cancelled')"
  ).bind(id,id),

  env.DB.prepare(
    "DELETE FROM attendance WHERE event_id=? AND EXISTS (SELECT 1 FROM events WHERE id=? AND status='cancelled')"
  ).bind(id,id),

  env.DB.prepare(
    "DELETE FROM events WHERE id=? AND status='cancelled'"
  ).bind(id)
]);

if(!results[2].meta.changes){
    return json({error:'Event was not deleted'},409);
  }

  return json({ok:true});
}
  return json({error:'Not found'},404);
 }catch(e){console.error('Bergholz API failure',method,path,e?.message||e);return json({error:'Request failed'},500)}
}
