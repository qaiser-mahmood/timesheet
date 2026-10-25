const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const path = require('path');
const test = require('node:test');
const html = fs.readFileSync(path.resolve(__dirname, '../index.html'), 'utf8');
const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
new vm.Script(script.replace(/^\s*import .*;\s*$/gm, ''));
const start = html.indexOf("document.getElementById('payForm').addEventListener('submit', async function(e) {");
const end = html.indexOf('\n                });', start);
const handlerSource = html.slice(start, end + '\n                });'.length);
function extractFunction(name) {
 const start = html.indexOf('function ' + name + '(');
 const end = html.indexOf('\n        async function getBookmarkletCodeString', start);
 return html.slice(start, end);
}
async function check(label, previous, total, expectedTax, expectedCash, store='anatolya', name='Staff') {
 let submit, saved, rendered;
 const fields = {totalHours:{value:String(total)},staffName:{value:name},date:{value:'2026-10-19'},startTime:{value:'09:00'},endTime:{value:'19:00'},payRate:{value:'20'},taxPayRate:{value:'25'},filterWeek:{value:'2026-10-19'},weekRangeDisplay:{},weeklyTableHead:{},weeklyTableBody:{},weeklyTableFoot:{},grandTotalHoursHeader:{},grandTotalPayoutHeader:{}};
 const context = { document:{getElementById:id=>id==='payForm'?{addEventListener:(_,fn)=>submit=fn}:fields[id]},dataStore:previous?[{date:'2026-10-19',weekCommencing:'2026-10-19',store_id:store,name,from:'09:00',to:'17:00',cashRate:20,taxRate:25,...previous}]:[],currentStore:store,staffRegistry:[{name,stores:[store]}],isShareModeActive:false, cleanDateStr:s=>s,getMondayString:()=> '2026-10-19',addDaysString:(d,i)=>'2026-10-'+String(19+i),formatDisplayDateStr:s=>s,convertTimeStr:s=>s,renderCurrentAnalyticsView:()=>{},mutationSequence:0,activeMutations:0,lastCloudFetchTime:0,callSheetApi:async p=>{saved=p.entry;return{}},loadCloudData:async()=>{},alert:m=>{throw Error(m)},console,escapeHtml:s=>String(s),getLocalTodayIso:()=> '2026-10-25'};
 vm.createContext(context);
 vm.runInContext(extractFunction('renderWeeklyTable'),context);
 vm.runInContext(handlerSource, context);
 await submit({preventDefault(){}});
 assert.equal(saved.totalHours,total,label+' total');
 assert.equal(saved.taxHours,expectedTax,label+' tax');
 assert.equal(saved.cashHours,expectedCash,label+' cash');
 if(name!=='qaiser') {
 assert.equal(saved.taxHours+saved.cashHours,total,label+' allocation');
 assert.equal(fields.grandTotalHoursHeader.innerText,total.toFixed(1),label+' pool');
 for(const hours of store==='green_juice'?[expectedCash]:[expectedTax,expectedCash]) {
 if(hours>0) assert.ok(fields.weeklyTableBody.innerHTML.includes('>'+hours.toFixed(1)+'</td>'),label+' employee column');
 }
 }
 console.log('PASS '+label);
}
test('roster duration edits reconcile paid hours and update employee columns (10 cases)', async()=>{
await check('extend mixed shift',{totalHours:8,taxHours:5,cashHours:3},10,5,5);
await check('shorten mixed shift',{totalHours:8,taxHours:5,cashHours:3},6,5,1);
await check('shorten below tax hours',{totalHours:8,taxHours:5,cashHours:3},4,4,0);
await check('cash-only shift',{totalHours:8,taxHours:0,cashHours:8},10,0,10);
await check('new shift',null,8,8,0);
await check('legacy shift',{totalHours:8},10,10,0);
await check('fractional shift',{totalHours:8,taxHours:5.5,cashHours:2.5},9.5,5.5,4);
await check('zero shift',{totalHours:8,taxHours:5,cashHours:3},0,0,0);
await check('Green Juice shift',{totalHours:8,taxHours:0,cashHours:8},10,0,10,'green_juice');
await check('owner shift',{totalHours:8,taxHours:0,cashHours:0},10,0,0,'anatolya','qaiser');
});

