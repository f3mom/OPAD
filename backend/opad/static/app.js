async function postJSON(url,data){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const t=await r.text();try{return JSON.parse(t)}catch{return{raw:t,status:r.status}}}
function show(id,obj){document.getElementById(id).textContent=JSON.stringify(obj,null,2)}
function nums(v){return v.split(',').map(x=>x.trim()).filter(Boolean).map(Number)}
async function saveScope(){const data={scope:{allowed_cidrs:document.getElementById('allowed_cidrs').value.split(',').map(x=>x.trim()).filter(Boolean),require_target_in_scope:true,exclude_own_team:true},game:{team_id:Number(document.getElementById('own_team').value)}};alert(JSON.stringify(await postJSON('/api/setup/save',{step:'scope',data}),null,2))}
async function saveGame(){const data={game:{name:document.getElementById('game_name').value,tick_duration_seconds:Number(document.getElementById('tick_duration').value),timezone:document.getElementById('timezone').value}};alert(JSON.stringify(await postJSON('/api/setup/save',{step:'game',data}),null,2))}
async function previewTargets(){show('targets_preview',await postJSON('/api/targets/generate',{pattern:document.getElementById('target_pattern').value,from:Number(document.getElementById('target_from').value),to:Number(document.getElementById('target_to').value),exclude:nums(document.getElementById('target_exclude').value)}))}
async function saveTargets(){const data={targets:{provider:'pattern',pattern:document.getElementById('target_pattern').value,from:Number(document.getElementById('target_from').value),to:Number(document.getElementById('target_to').value),exclude:nums(document.getElementById('target_exclude').value)}};alert(JSON.stringify(await postJSON('/api/setup/save',{step:'targets',data}),null,2))}
async function saveServices(){alert(JSON.stringify(await postJSON('/api/setup/save',{step:'services',data:{services:JSON.parse(document.getElementById('services_json').value)}}),null,2))}
async function generateFlagRegex(){const result=await postJSON('/api/flags/preset',{name:document.getElementById('flag_preset').value,alphabet:document.getElementById('flag_alphabet').value,length:Number(document.getElementById('flag_length').value),suffix:'='});document.getElementById('flag_regex').value=result.regex}
async function saveFlags(){const data={flags:{extractors:[{name:'primary',type:'regex',regex:document.getElementById('flag_regex').value}],normalize:{trim:true,uppercase:false},deduplicate:{enabled:true,by:'value_hash'},ttl:{mode:'ticks',value:5},fake_flag_protection:{enabled:true}}};alert(JSON.stringify(await postJSON('/api/setup/save',{step:'flags',data}),null,2))}
async function testFlags(){show('flag_test_result',await postJSON('/api/flags/extract-test',{regex:document.getElementById('flag_regex').value,text:document.getElementById('flag_test_text').value}))}
async function saveSubmitter(){const data={submitter:{type:document.getElementById('submitter_type').value,url:document.getElementById('submitter_url').value,method:'POST',headers:{Authorization:document.getElementById('submitter_auth').value},body:{flag:'{flag}'},queue:{rate_limit_per_second:5,batch_size:20,retry:true},verdicts:{ok:['OK','ACCEPTED'],duplicate:['DUP','DUPLICATE'],old:['OLD','EXPIRED'],invalid:['INVALID'],own:['OWN','SELF']}}};alert(JSON.stringify(await postJSON('/api/setup/save',{step:'submitter',data}),null,2))}
async function testSubmitter(){show('submitter_result',await postJSON('/api/submitter/test',{dry_run:true}))}
async function saveAgent(){const data={agent:{mode:document.getElementById('agent_mode').value,host:document.getElementById('agent_host').value,user:document.getElementById('agent_user').value,port:Number(document.getElementById('agent_port').value),workdir:'/opt/opad-agent'}};alert(JSON.stringify(await postJSON('/api/setup/save',{step:'agent',data}),null,2))}
async function savePatching(){const data={patching:{default_mode:'docker_compose',snapshot_before_deploy:document.getElementById('snapshot_before').checked,rollback_on_failed_healthcheck:document.getElementById('rollback_health').checked,services:{}}};alert(JSON.stringify(await postJSON('/api/setup/save',{step:'patching',data}),null,2))}
async function saveExploitRunner(){const data={exploit_runner:{directory:document.getElementById('exploit_dir').value,default_runtime:'python',timeout_seconds:Number(document.getElementById('exploit_timeout').value),parallelism:Number(document.getElementById('exploit_parallelism').value),auto_extract_flags:true,auto_submit:true,schedule:{default:'every_tick'}}};alert(JSON.stringify(await postJSON('/api/setup/save',{step:'exploits',data}),null,2))}
async function saveTraffic(){const data={traffic:{providers:{packmate:{enabled:document.getElementById('packmate_enabled').checked,mode:'external',url:document.getElementById('packmate_url').value,sync_services:true,sync_flag_patterns:true},native:{enabled:true}}}};alert(JSON.stringify(await postJSON('/api/setup/save',{step:'traffic',data}),null,2))}
async function packmateStatus(){const r=await fetch('/api/packmate/status');show('packmate_result',await r.json())}
async function packmateSyncPlan(){const r=await fetch('/api/packmate/sync-plan');show('packmate_result',await r.json())}
async function finalTest(){const r=await fetch('/api/setup/final-test');show('final_result',await r.json())}
async function completeSetup(){const r=await postJSON('/api/setup/complete',{});location.href=r.redirect||'/dashboard'}
async function healthcheck(service){show('health_result',await postJSON('/api/services/healthcheck',{service_name:service,host:'127.0.0.1'}))}
async function storeFlag(){show('manual_flag_result',await postJSON('/api/flags/store',{flag:document.getElementById('manual_flag').value,source_type:'manual'}))}
async function runExploit(name){show('exploit_result',await postJSON('/api/exploits/run',{name,target:'all'}))}
async function analyzeTraffic(){show('traffic_result',await postJSON('/api/traffic/analyze',{src_ip:document.getElementById('traffic_src').value,service_name:document.getElementById('traffic_service').value,request:document.getElementById('traffic_request').value,response:document.getElementById('traffic_response').value}))}
async function snapshotService(name){show('patch_result',await postJSON('/api/patches/snapshot',{service_name:name}))}

// --- OPAD v1: auth, integrations, defense filter apply-flow ---
async function loginOPAD(){const r=await postJSON('/api/auth/login',{username:document.getElementById('login_username').value,password:document.getElementById('login_password').value});show('login_result',r);if(r.ok){setTimeout(()=>location.href='/dashboard',600)}}
async function bootstrapAdmin(){const r=await postJSON('/api/auth/bootstrap',{username:document.getElementById('boot_username').value,password:document.getElementById('boot_password').value});show('bootstrap_result',r)}
async function authMe(){const r=await fetch('/api/auth/me');show('user_result',await r.json())}
async function createUser(){show('user_result',await postJSON('/api/users',{username:document.getElementById('new_user').value,password:document.getElementById('new_pass').value,role:document.getElementById('new_role').value}))}
async function createToken(){show('token_result',await postJSON('/api/tokens',{name:document.getElementById('token_name').value,role:document.getElementById('token_role').value}))}
async function integrationStatus(){const r=await fetch('/api/integrations/status');show('integration_status',await r.json())}
async function capturePlan(){const r=await fetch('/api/capture/pcap-broker-plan');show('capture_result',await r.json())}
async function packmateSyncServices(){show('packmate_ext_result',await postJSON('/api/integrations/packmate/sync-services',{dry_run:true}))}
async function packmateSyncPatterns(){show('packmate_ext_result',await postJSON('/api/integrations/packmate/sync-patterns',{dry_run:true}))}
async function packmateLookback(){show('packmate_ext_result',await postJSON('/api/integrations/packmate/lookback',{pattern:document.getElementById('lookback_pattern').value,minutes:Number(document.getElementById('lookback_minutes').value),dry_run:true}))}
async function tulipFlows(){const r=await fetch('/api/integrations/tulip/flows?q='+encodeURIComponent(document.getElementById('tulip_query').value)+'&dry_run=true');show('tulip_result',await r.json())}
async function tulipDraft(){show('tulip_result',await postJSON('/api/integrations/tulip/exploit-draft',{flow:{service:'shop',method:'GET',path:'/api/item?id=1',headers:{},body:''}}))}
async function pkappaUploadPlan(){const r=await fetch('/api/integrations/pkappa2/upload-plan?filename='+encodeURIComponent(document.getElementById('pkappa_file').value));show('pkappa_result',await r.json())}
async function pkappaQuery(){const r=await fetch('/api/integrations/pkappa2/query?q='+encodeURIComponent(document.getElementById('pkappa_query').value)+'&dry_run=true');show('pkappa_result',await r.json())}
async function shovelRule(){const q=new URLSearchParams({name:document.getElementById('shovel_name').value,pattern:document.getElementById('shovel_pattern').value,service_port:document.getElementById('shovel_port').value});const r=await fetch('/api/integrations/shovel/rule-draft?'+q.toString());show('shovel_result',await r.json())}
async function shovelAlerts(){const r=await fetch('/api/integrations/shovel/alerts?dry_run=true');show('shovel_result',await r.json())}
let currentFilterDraft=null;
async function draftFilterRule(){currentFilterDraft=await postJSON('/api/defense/rules/draft',{provider:document.getElementById('filter_provider').value,service_name:document.getElementById('filter_service').value,pattern:document.getElementById('filter_pattern').value,action:document.getElementById('filter_action').value,mode:document.getElementById('filter_mode').value});show('filter_result',currentFilterDraft);if(currentFilterDraft.rule_id){document.getElementById('apply_rule_id').value=currentFilterDraft.rule_id}}
async function stageFilterRule(){if(!currentFilterDraft){await draftFilterRule()}const r=await postJSON('/api/defense/rules/stage',{draft:currentFilterDraft});show('filter_result',r);if(r.rule_id){document.getElementById('apply_rule_id').value=r.rule_id}}
async function applyPlan(){show('apply_result',await postJSON('/api/defense/rules/apply-plan',{rule_id:document.getElementById('apply_rule_id').value}))}
async function applyRule(){show('apply_result',await postJSON('/api/defense/rules/apply',{rule_id:document.getElementById('apply_rule_id').value,checker_replay_passed:document.getElementById('checker_ok').checked,healthcheck_passed:document.getElementById('health_ok').checked,rollback_plan:document.getElementById('rollback_plan').value,confirm:document.getElementById('apply_confirm').value,dry_run:document.getElementById('apply_dry').checked}))}


// --- OPAD Ultra: generic web cockpit helpers ---
async function ultraGet(url, target){const r=await fetch(url);show(target, await r.json().catch(async()=>({raw:await r.text(),status:r.status})))}
async function ultraAction(action, target){show(target, await postJSON('/api/ultra/action', {action}))}
async function ultraRunAction(action, target){
  if(action.method === 'GET'){return ultraGet(action.endpoint, target)}
  const body = action.body || {action: action.key};
  show(target, await postJSON(action.endpoint, body));
}
