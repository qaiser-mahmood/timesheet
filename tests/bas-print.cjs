'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const vm=require('vm');
const html=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8');
function between(start,end){const a=html.indexOf(start),b=html.indexOf(end,a+start.length);assert.ok(a>=0&&b>a);return html.slice(a,b);}
function fixture(){
 const fields=Object.fromEntries(['basActualW1','basActualW2','basActualW3','basActualW4','basPrintBusiness','basPrintAbn','basPrintMethod','basPrintNotes'].map(id=>[id,{value:''}]));
 const listeners={};
 const c={document:{getElementById:id=>fields[id]||null},window:{addEventListener:(name,fn)=>listeners[name]=fn},
 currentStore:'all',currentBasFY:'2026',currentBasQuarter:'Q1',Intl,Date,
 cleanDateStr:s=>s,isStoreMatch:()=>true,isExpenseMatch:()=>true,formatDisplayDateStr:s=>s,
 hourlySalesStore:[{date:'2026-09-01',store_id:'anatolya',totalSales:165,cashSales:33,cardSales:110,uberSales:22}],
 expensesStore:[{date:'2026-09-02',store_id:'anatolya',category:'Packaging',amount:22}],
 BAS_GST_RULES:{Packaging:{taxable:true}}};
 vm.createContext(c);
 vm.runInContext(between('        function toLocalDateIso(', '        let isShareModeActive'),c);
 vm.runInContext(between('        function getBasQuarterDates(', '        function switchBasQuarter('),c);
 vm.runInContext(between('        function getBasSalesBreakdown(', '        function renderBasReportView()'),c);
 vm.runInContext(between('function collectBasPrintData()', '        function getBasSalesBreakdown('),c);
 c.getBasPayrollActuals();
 return {c,fields,listeners};
}
test('accountant summary maps GST, W5 and payment labels to whole-dollar figures',()=>{
 const {c,fields}=fixture();
 fields.basActualW1.value='1000.99';fields.basActualW2.value='120.99';fields.basActualW3.value='10';fields.basActualW4.value='5';
 const d=c.collectBasPrintData();
 assert.equal(d.g1,132);assert.equal(d.a1,12);assert.equal(d.b1,2);
 assert.equal(d.w1,1000);assert.equal(d.w2,120);assert.equal(d.w5,135);
 assert.equal(d.a8,147);assert.equal(d.b8,2);assert.equal(d.net,145);
 const report=c.buildBasPrintHtml(d);
 for(const code of ['G1','1A','1B','W1','W2','W3','W4','W5','4','8A','8B','9'])assert.ok(report.includes('>'+code+'</b>'),code);
 assert.equal((report.match(/class="bas-print-page"/g)||[]).length,2);
 assert.ok(report.includes('Alhamd Enterprises Pty Ltd'));assert.ok(report.includes('64 647 160 030'));assert.ok(report.includes('Cash'));
 assert.equal(d.monthly.reduce((sum,m)=>sum+m.included,0),d.includedSales);
});
test('missing payroll stays unconfirmed and explicit zeroes produce a known GST-only amount',()=>{
 const {c,fields}=fixture();
 let d=c.collectBasPrintData();assert.equal(d.w5,null);assert.equal(d.net,null);
 assert.ok(c.buildBasPrintHtml(d).includes('Not supplied / review'));
 for(const id of ['basActualW1','basActualW2','basActualW3','basActualW4'])fields[id].value='0';
 d=c.collectBasPrintData();assert.equal(d.w5,0);assert.equal(d.net,10);
});
test('a refund is printed as a positive label 9 amount with refund direction',()=>{
 const {c,fields}=fixture();
 for(const id of ['basActualW1','basActualW2','basActualW3','basActualW4'])fields[id].value='0';
 c.expensesStore[0].amount=220;
 const d=c.collectBasPrintData();assert.equal(d.net,-8);
 const report=c.buildBasPrintHtml(d);assert.ok(report.includes('Refund / credit'));assert.ok(report.includes('8<small>.00'));
});
test('accountant identity and notes are escaped and cash reconciliation is explicit',()=>{
 const {c,fields}=fixture();
 fields.basPrintBusiness.value='<img src=x onerror=bad()>';
 fields.basPrintNotes.value='<script>bad()</script>';
 const report=c.buildBasPrintHtml(c.collectBasPrintData());
 assert.ok(!report.includes('<script>'));assert.ok(!report.includes('<img'));
 assert.ok(report.includes('&lt;script&gt;'));
 assert.ok(report.includes('cash sales excluded'));assert.ok(report.includes('33.00'));assert.ok(report.includes('165.00'));
});
test('changing period clears W3 and W4 and print isolation leaves normal dashboard printing alone',()=>{
 const {c,fields,listeners}=fixture();
 fields.basActualW3.value='15';fields.basActualW4.value='20';
 c.currentBasQuarter='Q2';c.getBasPayrollActuals();
 assert.equal(fields.basActualW3.value,'');assert.equal(fields.basActualW4.value,'');
 c.currentAnalyticsTab='daily';listeners.beforeprint();
 assert.ok(html.includes('body.bas-print-active > :not(#basPrintReport)'));
 assert.ok(html.includes('@page { size: A4 portrait; margin: 12mm; }'));
});
