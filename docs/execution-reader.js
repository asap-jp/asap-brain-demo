/* ASAP Brain execution-record reader. Offline, dependency-free, read-only.
 * Supported adapters: Codex rollout update_plan / exec todo_list;
 * Claude Code TodoWrite, TaskCreate, TaskUpdate with matching tool results.
 * Text checklists are OPTIONAL review candidates, never confirmed tasks.
 * No command execution, network calls, raw-log export, or reasoning export.
 */
(function(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.ASAPExecutionReader = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';
  const VERSION = '1.2.0';
  const LIMITS = Object.freeze({bytes:25*1024*1024, line:1024*1024, records:150000, tasks:2000});
  const TERMINAL = new Set(['completed','cancelled','deleted','removed']);
  const STATES = new Map([['pending','ready'],['in_progress','running'],['completed','completed'],['deleted','deleted'],['cancelled','cancelled'],['blocked','blocked']]);
  const norm = s => String(s || '').normalize('NFKC').trim().replace(/\s+/g,' ');
  const pathNorm = p => typeof p === 'string' ? p.replace(/\\/g,'/').replace(/\/+$/,'') : '';
  const textOf = v => typeof v === 'string' ? v : Array.isArray(v) ? v.filter(x => x && (x.type === 'text' || x.type === 'output_text' || x.type === 'input_text')).map(x => x.text || '').join('\n') : '';
  const dateOf = s => typeof s === 'string' && /(?:Z|[+-]\d{2}:\d{2})$/.test(s) && Number.isFinite(Date.parse(s)) ? new Date(s).toISOString() : null;
  const safeId = s => typeof s === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(s) ? s : null;
  const error = code => { const e = new Error(code); e.code=code; return e; };
  const utf8Size = s => new TextEncoder().encode(s).length;
  async function digest(s) {
    let subtle = globalThis.crypto && globalThis.crypto.subtle;
    if (!subtle && typeof require === 'function') subtle = require('node:crypto').webcrypto.subtle;
    if (!subtle) return sha256Fallback(s);
    return Array.from(new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(s))), b=>b.toString(16).padStart(2,'0')).join('');
  }
  // Deterministic SHA-256 fallback for an offline file/preview without WebCrypto.
  // Used for evidence fingerprints, not for authentication or password hashing.
  function sha256Fallback(text) {
    const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    const data=new TextEncoder().encode(text), n=Math.ceil((data.length+9)/64)*64;
    const padded=new Uint8Array(n);padded.set(data);padded[data.length]=0x80;
    const view=new DataView(padded.buffer), bits=data.length*8;
    view.setUint32(n-8,Math.floor(bits/4294967296));view.setUint32(n-4,bits>>>0);
    const h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],w=new Uint32Array(64);
    const rr=(x,k)=>(x>>>k)|(x<<(32-k));
    for(let off=0;off<n;off+=64){
      for(let i=0;i<16;i++)w[i]=view.getUint32(off+i*4);
      for(let i=16;i<64;i++){const x=w[i-15],y=w[i-2];w[i]=(w[i-16]+(rr(x,7)^rr(x,18)^(x>>>3))+w[i-7]+(rr(y,17)^rr(y,19)^(y>>>10)))>>>0;}
      let [a,b,c,d,e,f,g,hh]=h;
      for(let i=0;i<64;i++){const t1=(hh+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^((~e)&g))+K[i]+w[i])>>>0;
        const t2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c)))>>>0;
        hh=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
      [a,b,c,d,e,f,g,hh].forEach((v,i)=>h[i]=(h[i]+v)>>>0);
    }
    return h.map(v=>v.toString(16).padStart(8,'0')).join('');
  }
  function redact(value, max=1000) {
    // Defense in depth only; review before export remains mandatory.
    let s = String(value || '');
    s = s.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g,'[非公開キーを除外]');
    s = s.replace(/\b(?:sk-(?:ant-)?[A-Za-z0-9_-]{12,}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{12,}|AIza[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g,'[認証情報を除外]');
    s = s.replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi,'Bearer [除外]');
    s = s.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,'[認証情報を除外]');
    s = s.replace(/((?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|password|passwd|authorization|cookie|パスワード|秘密鍵|トークン)\s*[=:：]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi,'$1[除外]');
    s = s.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,'[メールを除外]');
    s = s.replace(/(?<!\d)(?:\+81[- ]?|0)(?:70|80|90)[- ]?\d{4}[- ]?\d{4}(?!\d)/g,'[電話を除外]');
    s = s.replace(/\b(?:\d[ -]?){13,19}\b/g,'[長い番号を除外]');
    s = s.replace(/https?:\/\/[^\s<>"']+/g, u=> { try { const x=new URL(u); x.username='';x.password='';x.search='';x.hash='';return x.toString(); } catch { return '[URLを除外]'; } });
    s = s.replace(/(?:\/Users\/|\/home\/)[^/\s]+/g,'~').replace(/[A-Z]:[\\/]Users[\\/][^\\/\s]+/gi,'~');
    s = s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g,'');
    return s.length>max ? s.slice(0,max)+'…' : s;
  }
  function decode(text) {
    if (typeof text !== 'string' || utf8Size(text)>LIMITS.bytes) throw error('file_too_large');
    const lines=text.replace(/^\uFEFF/,'').split(/\r?\n/);
    if (lines.length>LIMITS.records) throw error('too_many_records');
    const records=[], warnings=[];
    let damaged=false;
    for(let i=0;i<lines.length;i++) {
      const line=lines[i]; if(!line.trim()) continue;
      if(utf8Size(line)>LIMITS.line) { damaged=true;warnings.push({code:'line_too_large',line:i+1});continue; }
      try { const r=JSON.parse(line);if(r && typeof r==='object' && !Array.isArray(r)) records.push({r,line:i+1});else throw error('bad_record'); }
      catch { damaged=true;warnings.push({code:i===lines.length-1?'partial_final_line':'invalid_json',line:i+1}); }
    }
    return {records,warnings,damaged};
  }
  function inspectDecoded(decoded) {
    const {records}=decoded, ids=new Set(), cwds=new Set(), sources=new Set();
    let paginated=false, sidechain=false, compacted=false;
    for(const {r} of records) {
      if(r.type==='session_meta') {
        sources.add('codex');if(r.payload?.id) ids.add(String(r.payload.id));if(r.payload?.cwd) cwds.add(pathNorm(r.payload.cwd));
        if(r.payload?.history_base || r.payload?.history_mode==='paginated' || r.payload?.forked_from_id) paginated=true;
      }
      if(r.type==='thread.started' && r.thread_id) { sources.add('codex');ids.add(String(r.thread_id)); }
      if(r.sessionId && ['assistant','user','system'].includes(r.type)) { sources.add('claude-code');ids.add(String(r.sessionId));if(r.cwd)cwds.add(pathNorm(r.cwd)); }
      if(r.type==='turn_context' && r.payload?.cwd) cwds.add(pathNorm(r.payload.cwd));
      if(r.type==='compacted' || r.type==='system' && r.subtype==='compact_boundary') compacted=true;
      if(r.isSidechain) sidechain=true;
    }
    if(sources.size>1 || ids.size>1) throw error('mixed_sessions');
    if(cwds.size>1) throw error('multiple_workspaces');
    return {sourceSystem:[...sources][0]||null,sessionId:safeId([...ids][0]),workspace:[...cwds][0]||null,paginated,sidechain,compacted,recordCount:records.length};
  }
  function inspectTranscript(text) { return inspectDecoded(decode(text)); }
  function readArgs(a) {if(a && typeof a==='object' && !Array.isArray(a))return a;if(typeof a==='string'){try{const v=JSON.parse(a);return v&&typeof v==='object'&&!Array.isArray(v)?v:null;}catch{}}return null;}
  function successful(output, source, flag) {
    if(flag===true) return false;
    if(output && typeof output==='object' && !Array.isArray(output)) return output.is_error!==true && output.error==null && output.success!==false;
    const s=textOf(output).trim();
    if(!s || /^(?:error\b|failed\b|tool execution failed|エラー|失敗)/i.test(s))return false;
    if(source==='codex')return /^(?:Plan updated|\{.*"(?:success|status)".*\})/s.test(s);
    return true; // Claude tool_result is authoritative only with is_error !== true.
  }
  function checklist(text) {
    const out=[];let fence=null, section=false;
    for(const raw of String(text||'').split(/\r?\n/)) {
      const line=raw.trim(), f=line.match(/^(`{3,}|~{3,})/);
      if(f){if(!fence)fence=f[1][0];else if(f[1][0]===fence)fence=null;continue;}
      if(fence || /^>/.test(line))continue;
      if(/^#{1,6}\s/.test(line)){section=/todo|残件|次の(?:作業|一手|手順)|未完了|確認待ち/i.test(line);continue;}
      let m=line.match(/^[-*+]\s+\[([ xX])\]\s+(.+)/);
      if(m)out.push({title:m[2],status:m[1].toLowerCase()==='x'?'completed':'unknown'});
      else if(section && (m=line.match(/^(?:[-*+]\s+|\d+[.)、]\s*)(.+)/)))out.push({title:m[1],status:'unknown'});
    }
    return out;
  }
  async function parseTranscript(text, options={}) {
    const d=decode(text), meta=inspectDecoded(d), warnings=[...d.warnings];
    const now=dateOf(options.observedAt || new Date().toISOString());
    if(!now)throw error('invalid_observed_at');
    if(!meta.sourceSystem)throw error('unsupported_format');
    if(!meta.sessionId)throw error('missing_session_identity');
    if(!options.project || !pathNorm(options.project))throw error('project_required');
    const project=pathNorm(options.project);
    const matches=meta.workspace===project || (options.includeSubprojects===true && meta.workspace?.startsWith(project+'/'));
    const attested = !meta.workspace && options.projectAttested === true;
    if(!matches && !attested)throw error(meta.workspace?'workspace_mismatch':'workspace_missing');
    if(attested)warnings.push({code:'workspace_supplied_not_in_log'});
    const calls=new Map(), taskMap=new Map(), textMap=new Map();
    let currentList=new Map(), removed=[], recognized=0, reset=false;
    let gap=d.damaged || meta.paginated || meta.compacted;
    if(meta.paginated)warnings.push({code:'partial_or_forked_history'});
    if(meta.compacted)warnings.push({code:'compacted_history'});
    if(meta.sidechain)warnings.push({code:'sidechain_records_skipped'});
    // Claude branching is conservative: mark extracted records for review rather than guessing active branch.
    const children=new Map();
    for(const {r} of d.records)if(r.parentUuid && r.uuid && !r.isSidechain){const a=children.get(r.parentUuid)||new Set();a.add(r.uuid);children.set(r.parentUuid,a);}
    if([...children.values()].some(a=>a.size>1)){gap=true;warnings.push({code:'branched_transcript_review_required'});}
    const row=(title,status,ev,extra={})=>({title:String(title||''),status,sourceLine:ev.line,sourceUpdatedAt:dateOf(ev.r.timestamp),evidenceType:'structured',...extra});
    function snapshot(items,ev,kind) {
      if(!Array.isArray(items) || items.length>LIMITS.tasks){gap=true;warnings.push({code:'invalid_task_snapshot',line:ev.line});return;}
      const next=new Map();
      for(const v of items){
        if(!v || typeof v!=='object'){gap=true;continue;}
        const title=kind==='codex-plan'?v.step:kind==='codex-exec'?v.text:v.content;
        const state=kind==='codex-exec'?(typeof v.completed==='boolean'?(v.completed?'completed':'ready'):'unknown'):STATES.get(v.status)||'unknown';
        if(typeof title!=='string'||!title.trim()){gap=true;continue;}
        const key=safeId(v.id)?`task:${safeId(v.id)}`:`title:${norm(title)}`;
        if(next.has(key)){gap=true;warnings.push({code:'duplicate_task_identity',line:ev.line});}
        next.set(key,row(title,state,ev,{sourceTaskId:safeId(v.id),identityKind:safeId(v.id)?'native':'derived_title',evidenceType:kind}));
      }
      for(const [k,v] of currentList)if(!next.has(k))removed.push({...v,status:'removed',exclusionReason:'absent_from_latest_snapshot'});
      currentList=next;recognized++;
    }
    function apply(call,result,ev) {
      if(call.name==='update_plan')snapshot(call.input.plan,ev,'codex-plan');
      if(call.name==='TodoWrite')snapshot(call.input.todos,ev,'claude-todos');
      if(call.name==='TaskCreate') {
        const data=readArgs(typeof result==='string'?result:textOf(result)) || (result && !Array.isArray(result)?result:null);
        const m=textOf(result).match(/Task\s+#([A-Za-z0-9_.:-]+)\s+created/i);
        const id=safeId(String(data?.task?.id || data?.taskId || data?.id || m?.[1] || ''));
        if(!id){gap=true;warnings.push({code:'task_create_id_missing',line:ev.line});return;}
        if(typeof call.input.subject!=='string'){gap=true;return;}
        taskMap.set(id,row(call.input.subject,'ready',ev,{sourceTaskId:id,identityKind:'native',evidenceType:'claude-task'}));recognized++;
      }
      if(call.name==='TaskUpdate') {
        const id=safeId(String(call.input.taskId||'')),old=taskMap.get(id);
        if(!old){gap=true;warnings.push({code:'task_update_without_create',line:ev.line});return;}
        const state=call.input.status==null?old.status:STATES.get(call.input.status)||'unknown';
        taskMap.set(id,row(call.input.subject||old.title,state,ev,{sourceTaskId:id,identityKind:'native',evidenceType:'claude-task'}));recognized++;
      }
    }
    for(const ev of d.records) {
      const r=ev.r;if(r.isSidechain)continue;
      const p=r.payload;
      if(r.type==='event_msg' && p?.type==='thread_rolled_back') {gap=true;reset=true;currentList.clear();taskMap.clear();textMap.clear();removed=[];calls.clear();warnings.push({code:'rollback_history_requires_review',line:ev.line});continue;}
      if(r.type==='response_item' && p?.type==='function_call') {
        const name=String(p.name||'').replace(/^functions\./,'');
        if(name==='update_plan' && p.call_id){const input=readArgs(p.arguments);if(input)calls.set(p.call_id,{name,input});else{gap=true;warnings.push({code:'invalid_plan_arguments',line:ev.line});}}
      }
      if(r.type==='response_item' && p?.type==='function_call_output' && calls.has(p.call_id)){
        const call=calls.get(p.call_id);calls.delete(p.call_id);
        if(successful(p.output,'codex',p.is_error))apply(call,p.output,ev);else {gap=true;warnings.push({code:'plan_update_failed_or_unverified',line:ev.line});}
      }
      if(/^item\.(?:started|updated|completed)$/.test(r.type) && r.item?.type==='todo_list')snapshot(r.item.items,ev,'codex-exec');
      if(r.type==='assistant' && r.message?.role==='assistant' && Array.isArray(r.message.content)){
        for(const b of r.message.content){
          if(b.type==='tool_use' && ['TodoWrite','TaskCreate','TaskUpdate'].includes(b.name) && b.id){const input=readArgs(b.input);if(input)calls.set(b.id,{name:b.name,input});}
        }
      }
      if(r.type==='user' && Array.isArray(r.message?.content))for(const b of r.message.content){
        if(b.type==='tool_result' && calls.has(b.tool_use_id)){
          const call=calls.get(b.tool_use_id);calls.delete(b.tool_use_id);
          if(successful(b.content,'claude-code',b.is_error))apply(call,b.content,ev);else{gap=true;warnings.push({code:'task_write_failed',line:ev.line});}
        }
      }
      if(options.includeTextCandidates===true){
        let t='';
        // NEVER inspect reasoning/system/user/tool-return text for inferred tasks.
        if(r.type==='response_item' && p?.type==='message' && p.role==='assistant' && p.channel!=='analysis')t=textOf(p.content);
        if(r.type==='assistant' && r.message?.role==='assistant')t=textOf(r.message.content);
        if(r.type==='item.completed' && r.item?.type==='agent_message')t=r.item.text;
        for(const v of checklist(t))textMap.set(norm(v.title),row(v.title,v.status,ev,{sourceTaskId:null,identityKind:'derived_title',evidenceType:'text_candidate'}));
      }
    }
    if(calls.size){gap=true;warnings.push({code:'task_call_without_result',count:calls.size});}
    const structured=[...currentList.values(),...taskMap.values()];
    const titles=new Set(structured.map(v=>norm(v.title)));
    // Explicit checklist completion after a structured step is a conflict requiring review, not proof.
    for(const v of structured){const t=textMap.get(norm(v.title));if(t && t.sourceLine>v.sourceLine && t.status==='completed' && v.status!=='completed'){v.conflict='later_text_claims_completion';}}
    const rows=[...structured,...[...textMap.values()].filter(v=>!titles.has(norm(v.title))),...removed.filter(v=>!titles.has(norm(v.title)))];
    if(rows.length>LIMITS.tasks)throw error('too_many_tasks');
    const sourceFileHash=await digest(text), workspaceId=await digest(project), output=[];
    for(const r of rows){
      const rawTitle=norm(r.title), sid=r.sourceTaskId || `derived-${(await digest(rawTitle)).slice(0,32)}`;
      const key=`${meta.sourceSystem}:${meta.sessionId}:${r.evidenceType==='claude-task'?'task':'plan'}:${sid}`;
      const title=redact(rawTitle,240), review=[];
      if(gap)review.push('history_incomplete_or_unverified');
      if(attested)review.push('workspace_supplied_not_in_log');
      if(r.evidenceType==='text_candidate')review.push('inferred_text_not_confirmed_task');
      if(r.status==='unknown')review.push('task_status_unknown');
      if(!r.sourceUpdatedAt)review.push('source_time_unknown');
      if(r.sourceUpdatedAt && r.sourceUpdatedAt>now)review.push('source_time_in_future');
      if(r.sourceUpdatedAt && Date.parse(now)-Date.parse(r.sourceUpdatedAt)>30*86400000)review.push('stale_source');
      if(r.conflict)review.push(r.conflict);
      if(title!==rawTitle)review.push('redacted_or_truncated_review_required');
      const out={sourceSystem:meta.sourceSystem,sourceScope:meta.sessionId,sourceId:sid,sourceTaskId:r.sourceTaskId,
        identityKind:r.identityKind,externalKey:key,sourceUrl:null,sourceUpdatedAt:r.sourceUpdatedAt,observedAt:now,
        title,status:r.status,kind:'task',brand:'',ideal:'',doneCriteria:'',
        currentState:`実行記録の最終状態: ${r.status}。業務完了の独立検証ではありません。`,
        nextAction:'元の業務文脈と既存ToDoを照合する。',blocker:'',agent:meta.sourceSystem==='codex'?'Codex':'Claude Code',
        taskIntentConfirmed:r.evidenceType!=='text_candidate',sourceDueDate:null,
        evidence:{type:r.evidenceType,line:r.sourceLine,fileSha256:sourceFileHash,workspaceId:workspaceId.slice(0,24)},
        classification:TERMINAL.has(r.status)?'excluded':review.length?'review':'candidate',
        reasons:TERMINAL.has(r.status)?[r.exclusionReason||'source_terminal_state']:review};
      out.fingerprint=await digest(JSON.stringify([key,title,r.status,r.sourceUpdatedAt,r.evidenceType]));output.push(out);
    }
    const unique=new Map();for(const v of output){const old=unique.get(v.externalKey);if(!old || (v.evidence.line||0)>(old.evidence.line||0))unique.set(v.externalKey,v);}
    const observations=[...unique.values()];
    if(!recognized && !observations.length)warnings.push({code:'no_explicit_tasks_found'});
    return {schemaVersion:1,readerVersion:VERSION,observedAt:now,sourceSystem:meta.sourceSystem,sourceScope:meta.sessionId,
      workspaceLabel:redact(project.split('/').pop()||'選択プロジェクト',80),workspaceId:workspaceId.slice(0,24),
      incomplete:gap,rollbackSeen:reset,observations,tasks:observations.filter(v=>v.classification!=='excluded'),
      excluded:observations.filter(v=>v.classification==='excluded'),warnings,
      counts:{candidate:observations.filter(v=>v.classification==='candidate').length,review:observations.filter(v=>v.classification==='review').length,excluded:observations.filter(v=>v.classification==='excluded').length},
      privacy:'Selected execution records only. No network, commands, source edits, reasoning or raw transcript export. Review redactions before sharing.'};
  }
  function combineSnapshots(snapshots, existing=[]) {
    if(!Array.isArray(snapshots)||!Array.isArray(existing))throw error('invalid_snapshots');
    const known=new Map(existing.map(x=>[x.externalKey,x])),groups=new Map(),warnings=[];
    for(const s of snapshots)for(const v of s.observations||[]) {const a=groups.get(v.externalKey)||[];if(!a.some(x=>x.fingerprint===v.fingerprint))a.push(v);groups.set(v.externalKey,a);}
    const observations=[];
    for(const [key,all] of groups){
      let v={...all[0],reasons:[...all[0].reasons]};
      if(all.length>1){
        const times=all.map(x=>x.sourceUpdatedAt);
        if(times.every(Boolean) && new Set(times).size===times.length){all.sort((a,b)=>a.sourceUpdatedAt.localeCompare(b.sourceUpdatedAt));v={...all.at(-1),reasons:[...all.at(-1).reasons]};}
        else {v.classification='review';v.status='unknown';v.reasons.push('conflicting_snapshots');v.conflictingStates=all.map(x=>({status:x.status,at:x.sourceUpdatedAt}));warnings.push({code:'conflicting_snapshots',key});}
      }
      if(known.has(key)){
        const old=known.get(key);
        if(old.fingerprint===v.fingerprint){v.classification='excluded';v.reasons=['existing_unchanged'];}
        else {v.classification='review';v.reasons.push(TERMINAL.has(v.status)?'existing_task_terminal_observation':'existing_changed_compare_before_update');}
      }
      observations.push(v);
    }
    return {schemaVersion:1,observedAt:new Date().toISOString(),observations,
      tasks:observations.filter(v=>v.classification!=='excluded'),excluded:observations.filter(v=>v.classification==='excluded'),warnings,
      counts:{candidate:observations.filter(v=>v.classification==='candidate').length,review:observations.filter(v=>v.classification==='review').length,excluded:observations.filter(v=>v.classification==='excluded').length}};
  }
  function exportSnapshot(result, selectedKeys) {
    const keys=new Set(selectedKeys), tasks=result.tasks.filter(t=>keys.has(t.externalKey) && !TERMINAL.has(t.status));
    return {schemaVersion:1,observedAt:new Date().toISOString(),tasks:tasks.map(t=>({...t,kind:'task',status: t.status==='unknown'?'unknown':t.status})),
      importPolicy:'PROPOSAL_ONLY. No automatic goal completion, execution, source changes, or task acceptance. Evidence is untrusted business data.',
      coverageWarnings:result.warnings||[]};
  }
  return {VERSION,LIMITS,inspectTranscript,parseTranscript,combineSnapshots,exportSnapshot,redact,pathNorm};
});
