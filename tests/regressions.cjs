'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const server = fs.readFileSync(path.join(root, 'epos-sync-worker/server.js'), 'utf8');
function sourceBetween(source, start, end) {
 const a = source.indexOf(start); assert.notEqual(a, -1, start);
 const b = source.indexOf(end, a + start.length); assert.notEqual(b, -1, end);
 return source.slice(a, b);
}
function worker() {
 const routes = [];
 const app = {use(){},listen(){}};
 for (const method of ['get','post','all']) app[method] = (route,...handlers) => routes.push({method,route,handlers});
 const express = () => app; express.json = express.urlencoded = () => () => {};
 let clock = Date.now();
 const context = {
  require: name => name === 'express' ? express : name === 'dotenv' ? {config(){}} :
   name === 'node-cron' ? {schedule(){}} : name === 'playwright' ? {chromium:{}} :
   name === 'fs' ? {existsSync:()=>false,writeFileSync(){}} : require(name),
  process:{env:{LOYVERSE_TOKEN:'test',SUPABASE_SERVICE_ROLE_KEY:'test'},uptime:()=>0},
  __dirname:path.join(root,'epos-sync-worker'), Buffer,URL,Intl,
  Date:class extends Date {static now(){return clock;}},
  console:{log(){},warn(){},error(){}},setTimeout,clearTimeout,
  fetch:async()=>{throw Error('Unexpected network call');}
 };
 vm.createContext(context);vm.runInContext(server,context);
 return {context,routes,advance:ms=>{clock+=ms;},route:p=>{const r=routes.find(r=>r.route===p);assert.ok(r,p);return r;}};
}
function response() {
 return {statusCode:200,body:null,headers:{},status(n){this.statusCode=n;return this;},
 json(v){this.body=v;return this;},send(v){this.body=v;return this;},
 setHeader(k,v){this.headers[k]=v;}};
}
function dbResponse(value=[],ok=true) {
 return {ok,status:ok?200:400,headers:{get:()=> 'application/json'},json:async()=>value,text:async()=> 'schema error'};
}
test('dangerous runtime evaluators are absent and operational routes require manager login',async()=>{
 const w=worker();
 assert.ok(!w.routes.some(r=>['/debug/eval','/debug/eval-node'].includes(r.route)));
 for(const p of ['/debug/screenshot','/debug/screentext','/debug/dom-inspect','/debug/login','/debug/apply-filter','/sync-reset','/sync-status','/api/expenses/parse-document','/api/bookmarklet-token']){
  const r=w.route(p);assert.equal(r.handlers[0],w.context.requireAuthorizedManager,p);
  const res=response();let next=false;
  await r.handlers[0]({headers:{}},res,()=>{next=true;});
  assert.equal(res.statusCode,401,p);assert.equal(next,false);
 }
});
test('bookmarklet tokens are upload-only and expire',async()=>{
 const w=worker(),r=w.route('/api/bookmarklet-sync');
 let res=response(),next=false;
 r.handlers[0]({headers:{}},res,()=>next=true);
 assert.equal(res.statusCode,401);assert.equal(next,false);
 res=response();w.route('/api/bookmarklet-token').handlers[1]({},res);
 const token=res.body.token;assert.match(token,/^[a-f0-9]{64}$/);
 res=response();r.handlers[0]({headers:{authorization:'Bearer '+token}},res,()=>next=true);assert.equal(next,true);
 res=response();await w.context.requireAuthorizedManager({headers:{authorization:'Bearer '+token}},res,()=>assert.fail('upload token granted manager access'));assert.equal(res.statusCode,401);
 w.advance(15*60*1000+1);res=response();r.handlers[0]({headers:{authorization:'Bearer '+token}},res,()=>assert.fail('expired token accepted'));assert.equal(res.statusCode,401);
});
test('roster writes and deletes never drop the shop scope on failure',async()=>{
 const w=worker();let calls=[];w.context.fetch=async(url,opts)=>{calls.push({url,opts});return dbResponse([],false);};
 const handler=w.route('/api/mutate').handlers[1];
 let res=response();
 await handler({body:{action:'save',entry:{date:'2026-10-19',name:'Staff',store_id:'green_juice',totalHours:8}}},res);
 assert.equal(res.statusCode,500);assert.equal(calls.length,1);assert.ok(calls[0].url.includes('on_conflict=date,name,store_id'));
 calls=[];res=response();
 await handler({body:{action:'delete',date:'2026-10-19',name:'Staff',store_id:'green_juice'}},res);
 assert.equal(res.statusCode,500);assert.equal(calls.length,1);assert.ok(calls[0].url.includes('store_id=eq.green_juice'));assert.ok(calls[0].url.includes('name=eq.'));
});
test('zero staff rates survive data loading',async()=>{
 const w=worker();
 w.context.fetch=async url=>dbResponse(url.includes('/staff?')?[{name:'Staff',cash_rate:0,tax_rate:0,gj_cash_rate:0,gj_sunday_rate:0}]:[]);
 const res=response();await w.route('/api/data').handlers[1]({},res);
 assert.equal(res.statusCode,200);
 const staff=res.body.staff[0];
 for(const key of ['cashRate','taxRate','gjCashRate','gjSundayRate'])assert.equal(staff[key],0,key);
});
test('Loyverse fetches beyond 5,000 receipts before saving complete totals',async()=>{
 const w=worker();let pages=0,writes=[];
 w.context.fetch=async(url,opts)=>{
  if(url.includes('api.loyverse.com')) {
   pages++;return dbResponse({receipts:Array.from({length:250},()=>({created_at:new Date().toISOString(),total_money:1,payments:[]})),cursor:pages<21?'page-'+pages:null});
  }
  writes.push(JSON.parse(opts.body));return dbResponse();
 };
 const result=await w.context.syncLoyverseSales();
 assert.equal(pages,21);assert.equal(result.totalSales,5250);assert.equal(writes.length,1);
});
test('Loyverse repeated cursor fails before saving partial totals',async()=>{
 const w=worker();let writes=0;
 w.context.fetch=async(url)=> {
  if(url.includes('api.loyverse.com'))return dbResponse({receipts:[{created_at:new Date().toISOString(),total_money:1}],cursor:'stuck'});
  writes++;return dbResponse();
 };
 await assert.rejects(w.context.syncLoyverseSales(),/repeated a cursor/);
 assert.equal(writes,0);
});
test('Epos range validation and splitting preserve requested dates',()=>{
 const w=worker();
 assert.throws(()=>w.context.validateSyncRange('2026-02-30','2026-03-01'));
 assert.throws(()=>w.context.validateSyncRange('2026-10-25','2026-10-01'));
 w.context.validateSyncRange('2026-09-01','2026-10-25');
 const ranges=w.context.splitDateRangeIntoChunks('2026-09-01','2026-10-25',31);
 assert.equal(ranges[0].from,'2026-09-01');assert.equal(ranges.at(-1).to,'2026-10-25');
});
test('calendar dates and business today use intended calendar without UTC shifts',()=>{
 const source=sourceBetween(html,'        function toLocalDateIso(', '        let isShareModeActive');
 const today=sourceBetween(html,'                function getLocalTodayIso()', '                window.getLocalTodayIso');
 const c={Intl,Date};vm.createContext(c);vm.runInContext(source+today,c);
 assert.equal(c.toLocalDateIso(new Date(2026,9,1)), '2026-10-01');
 assert.equal(c.getLocalTodayIso(),new Intl.DateTimeFormat('en-CA',{timeZone:'Australia/Perth'}).format(new Date()));
});
test('HTML escaping protects notes and attribute values',()=>{
 const source=sourceBetween(html,'        function escapeHtml(', '        function numberOrDefault(');
 const c={};vm.createContext(c);vm.runInContext(source,c);
 const escaped=c.escapeHtml('<img src=x onerror="bad()"> & \'');
 assert.equal(escaped,'&lt;img src=x onerror=&quot;bad()&quot;&gt; &amp; &#39;');
 assert.ok(html.includes('x.notes ? escapeHtml(x.notes)'));
 assert.ok(html.includes('const safeNotes = escapeHtml(r.notes'));
 assert.ok(html.includes('deleteLearnedRule(this.dataset.keyword)'));
});
test('failed mutation performs one request and never retries direct database writes',async()=>{
 const src=sourceBetween(html,'                async function callSheetApi(', '                let isCloudLoading');
 let calls=0;
 const c={auth:{currentUser:{email:'manager',getIdToken:async()=> 'token'}},isAuthorizedEmail:()=>true,AbortController,setTimeout,clearTimeout,EPOS_WORKER_URL:'https://example.invalid',fetch:async()=>{calls++;throw new TypeError('network');},TypeError};
 vm.createContext(c);vm.runInContext(src,c);
 await assert.rejects(c.callSheetApi({action:'save_expense',expense:{amount:100}}),/Refresh and check/);assert.equal(calls,1);
 assert.ok(!html.includes('async function supabaseFetch'));
});
test('BAS actual payroll defaults to unknown, preserves explicit zero, resets between periods',()=>{
 const fields={basActualW1:{value:''},basActualW2:{value:''}};
 const c={document:{getElementById:id=>fields[id]},currentStore:'anatolya',currentBasFY:'2026',currentBasQuarter:'Q1'};
 vm.createContext(c);vm.runInContext(sourceBetween(html,'        function getBasSalesBreakdown(', '        function renderBasReportView()'),c);
 assert.equal(c.getBasPayrollActuals().w2,null);
 fields.basActualW1.value='1000';fields.basActualW2.value='0';
 assert.equal(c.getBasPayrollActuals().w1,1000);assert.equal(c.getBasPayrollActuals().w2,0);
 c.currentBasQuarter='Q2';assert.equal(c.getBasPayrollActuals().w2,null);
 assert.ok(html.includes('const totalSalesG1 = totalIncludedSales;'));
 assert.ok(!html.includes('ESTIMATED_TAX_RATE'));
 assert.ok(html.includes('netGstBox3 + payrollActuals.w2'));
});

test('Epos sync applies every requested range and records a fresh result',async()=>{
 const w=worker(),applied=[];
 w.context.ensureLoggedIn=async()=>({goto:async()=>{},waitForLoadState:async()=>{},waitForTimeout:async()=>{}});
 w.context.applyEposDateFilter=async(page,from,to)=>applied.push({from,to});
 w.context.scrapeAndSaveCurrentPage=async(page,label,notify,from,to)=>({daysBatch:[{date:from,totalSales:10}],totalTx:1,pagesLoaded:1});
 const result=await w.context.runSync(true,false,'2026-09-01','2026-10-25');
 assert.equal(applied.length,2);assert.equal(applied[0].from,'2026-09-01');assert.equal(applied[1].to,'2026-10-25');assert.equal(result.txCount,2);
});
test('busy sync is reported as in progress rather than a completed stale result',async()=>{
 const w=worker();vm.runInContext('appState.isSyncing = true;',w.context);
 const res=response();await w.route('/sync').handlers[1]({query:{wait:'true'}},res);
 assert.equal(res.statusCode,409);assert.equal(res.body.status,'in_progress');
});
test('filter failures stop the Epos scrape instead of saving the wrong period',async()=>{
 const w=worker();
 const locator={count:async()=>{throw Error('filter unavailable');}};
 await assert.rejects(w.context.applyEposDateFilter({locator:()=>locator},'2026-09-20','2026-09-20',false),/filter unavailable/);
 assert.ok(!server.includes("fromIso === '2026-09-20'"));assert.ok(!server.includes("fromIso === '2026-09-21'"));
});
test('Epos client includes the selected dates and shows failure when worker rejects the sync',async()=>{
 let requested,status=[];
 const element={disabled:false,innerText:'',classList:{add(){},remove(){}}};
 const c={auth:{currentUser:{email:'manager',getIdToken:async()=> 'manager-token'}},isAuthorizedEmail:()=>true,isCloudLoading:false,
 document:{getElementById:()=>element},URLSearchParams,AbortController,setTimeout:()=>0,clearTimeout(){},setRefreshSpinners(){},
 EPOS_WORKER_URL:'https://example.invalid',console:{error(){},warn(){}},loadCloudData:async()=>{},
 fetch:async url=>{requested=url;return {ok:false,json:async()=>({message:'Sync failed'})};}};
 vm.createContext(c);vm.runInContext(sourceBetween(html,'                async function syncDirectFromEpos(', '                function parseStoresList('),c);
 await c.syncDirectFromEpos('2026-09-01','2026-09-30');
 assert.ok(requested.includes('from=2026-09-01'));assert.ok(requested.includes('to=2026-09-30'));
 assert.ok(element.innerText.includes('Sync not completed'));
});
test('generated bookmarklet includes only the scoped upload token and parses as JavaScript',async()=>{
 const c={auth:{currentUser:{email:'manager',getIdToken:async()=> 'manager-secret'}},isAuthorizedEmail:()=>true,EPOS_WORKER_URL:'https://example.invalid',fetch:async()=>({ok:true,json:async()=>({token:'upload-token'})})};
 vm.createContext(c);vm.runInContext(sourceBetween(html,'        async function getBookmarkletCodeString(', '        async function openEposModal('),c);
 const code=await c.getBookmarkletCodeString();
 assert.ok(code.includes('upload-token'));assert.ok(!code.includes('manager-secret'));assert.ok(code.includes('Authorization'));
 new vm.Script(code.slice('javascript:'.length));
});
test('BAS worksheet excludes cash, includes delivery sales and uses actual payroll',()=>{
 const fields={basActualW1:{value:''},basActualW2:{value:''},basBoxG1:{},basBox1A:{},basBoxW1:{},basBoxW2:{},basTotalPayable:{}};
 const c={document:{getElementById:id=>fields[id]||null},currentStore:'all',currentBasFY:'2026',currentBasQuarter:'Q1',
 updateBasQuarterButtonsUI(){},getBasQuarterDates:()=>({start:'2026-07-01',end:'2026-09-30',title:'Q1',days:92,months:[]}),
 hourlySalesStore:[{date:'2026-09-01',store_id:'anatolya',totalSales:165,cardSales:110,cashSales:33,uberSales:22}],
 expensesStore:[],dataStore:[],EXPENSE_CATEGORIES:[],BAS_GST_RULES:{},cleanDateStr:s=>s,isStoreMatch:()=>true,isExpenseMatch:()=>true,
 formatDisplayDateStr:s=>s};
 vm.createContext(c);vm.runInContext(sourceBetween(html,'        function getBasSalesBreakdown(', '        function computePeriodFinancials('),c);
 vm.runInContext(sourceBetween(html,'        function numberOrDefault(', '        let isShareModeActive'),c);
 c.renderBasReportView();assert.equal(fields.basBoxG1.innerText,'$132.00');assert.equal(fields.basBox1A.innerText,'$12.00');
 assert.equal(fields.basBoxW2.innerText,'Payroll required');assert.equal(fields.basTotalPayable.innerText,'Payroll required');
 fields.basActualW1.value='1000';fields.basActualW2.value='120';c.renderBasReportView();
 assert.equal(fields.basBoxW1.innerText,'$1000.00');assert.equal(fields.basBoxW2.innerText,'$120.00');assert.equal(fields.basTotalPayable.innerText,'$132.00');
});

test('Epos aborts without writing when pagination stalls',async()=>{
 const w=worker();let writes=0;
 w.context.fetch=async()=>{writes++;return dbResponse();};
 const emptyLocator={first(){return this;},count:async()=>0};
 const row={eposId:'one',date:'2026-10-25',time:'12:00',hour:'12:00',amount:10,isCash:false,raw:'row'};
 let evaluations=0;
 const page={locator:()=>emptyLocator,waitForTimeout:async()=>{},evaluate:async()=>{
  evaluations++;if(evaluations===1)return [row];if(evaluations===2)return true;return 'one';
 }};
 await assert.rejects(w.context.scrapeAndSaveCurrentPage(page,'test',false),/pagination did not advance/);
 assert.equal(writes,0);
});
test('Epos rejects out-of-range transactions before database writes',async()=>{
 const w=worker();let writes=0,evaluations=0;
 w.context.fetch=async()=>{writes++;return dbResponse();};
 const emptyLocator={first(){return this;},count:async()=>0};
 const row={eposId:'one',date:'2026-10-25',time:'12:00',hour:'12:00',amount:10,isCash:false,raw:'row'};
 const page={locator:()=>emptyLocator,waitForTimeout:async()=>{},evaluate:async()=>++evaluations===1?[row]:false};
 await assert.rejects(w.context.scrapeAndSaveCurrentPage(page,'test',false,'2026-09-01','2026-09-30'),/outside the selected range/);
 assert.equal(writes,0);
});
test('Epos database write failures cannot be reported as success',async()=>{
 const w=worker();let evaluations=0;
 w.context.fetch=async()=>dbResponse([],false);
 const emptyLocator={first(){return this;},count:async()=>0};
 const row={eposId:'one',date:'2026-10-25',time:'12:00',hour:'12:00',amount:10,isCash:false,raw:'row'};
 const page={locator:()=>emptyLocator,waitForTimeout:async()=>{},evaluate:async()=>++evaluations===1?[row]:false};
 await assert.rejects(w.context.scrapeAndSaveCurrentPage(page,'test',false),/Sales database write failed/);
});

test('cash exclusion preserves refunds, explicit zero cash and legacy payment splits',()=>{
 const c={};vm.createContext(c);
 vm.runInContext(sourceBetween(html,'        function numberOrDefault(', '        let isShareModeActive'),c);
 vm.runInContext(sourceBetween(html,'        function getBasSalesBreakdown(', '        let basPayrollPeriodKey'),c);
 const cases=[
  [{totalSales:110,cardSales:0,cashSales:110},0],
  [{totalSales:110,cardSales:110,cashSales:0},110],
  [{totalSales:165,cardSales:110,cashSales:33,uberSales:22},132],
  [{totalSales:-55,cardSales:-33,cashSales:-22},-33],
  [{totalSales:165,hourly:{_cardSales:110,_cashSales:33,_uberSales:22}},132],
  [{totalSales:165,cardSales:110,uberSales:22},132],
  [{totalSales:110},110]
 ];
 for(const [record,expected] of cases)assert.equal(c.getBasSalesBreakdown(record).included,expected);
});
test('venue and monthly GST subtotals use the same cash-excluded sales scope',()=>{
 const fields={basActualW1:{value:''},basActualW2:{value:''},basBoxG1:{},basBox1A:{},basStoreBreakdownTableBody:{},basMonthlyTableBody:{}};
 const c={document:{getElementById:id=>fields[id]||null},currentStore:'all',currentBasFY:'2026',currentBasQuarter:'Q1',
 updateBasQuarterButtonsUI(){},getBasQuarterDates:()=>({start:'2026-07-01',end:'2026-09-30',title:'Q1',days:92,months:[{key:'2026-09',name:'September',start:'2026-09-01',end:'2026-09-30'}]}),
 hourlySalesStore:[{date:'2026-09-01',store_id:'anatolya',totalSales:165,cardSales:110,cashSales:33,uberSales:22}],
 expensesStore:[],dataStore:[],EXPENSE_CATEGORIES:[],BAS_GST_RULES:{},cleanDateStr:s=>s,isStoreMatch:()=>true,isExpenseMatch:()=>true,formatDisplayDateStr:s=>s};
 vm.createContext(c);
 vm.runInContext(sourceBetween(html,'        function numberOrDefault(', '        let isShareModeActive'),c);
 vm.runInContext(sourceBetween(html,'        function getBasSalesBreakdown(', '        function computePeriodFinancials('),c);
 c.renderBasReportView();
 assert.equal(fields.basBoxG1.innerText,'$132.00');
 for(const id of ['basStoreBreakdownTableBody','basMonthlyTableBody']){
  assert.ok(fields[id].innerHTML.includes('$132.00'),id+' included sales');
  assert.ok(fields[id].innerHTML.includes('$12.00'),id+' GST');
  assert.ok(!fields[id].innerHTML.includes('$15.00'),id+' must exclude cash GST');
 }
});

test('Anatolya Sync opens the date-range dialog instead of immediately scraping today',()=>{
 const calls=[];
 const c={currentStore:'anatolya',openEposSyncModal:()=>calls.push('epos-range'),openLoyverseSyncModal:()=>calls.push('loyverse'),openActiveStoreSyncModal:()=>calls.push('active'),syncDirectFromEpos:()=>assert.fail('must choose a date range first')};
 vm.createContext(c);vm.runInContext(sourceBetween(html,'                function handlePanelSyncClick()', '                function updateSyncButtonUI()'),c);
 c.handlePanelSyncClick();assert.equal(calls.pop(),'epos-range');
 c.currentStore='green_juice';c.handlePanelSyncClick();assert.equal(calls.pop(),'loyverse');
});
