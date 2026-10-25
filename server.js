const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3000;
const DATA = path.join(__dirname, 'data.json');
app.use(express.json({limit:'20kb'}));
app.use(express.static(path.join(__dirname, 'public')));
function readData(){try{return JSON.parse(fs.readFileSync(DATA,'utf8'))}catch{return []}}
function saveData(items){fs.writeFileSync(DATA,JSON.stringify(items,null,2))}
app.get('/api/health',(req,res)=>res.json({status:'ok',application:'Phishing URL Detector'}));
app.post('/api/check-url',(req,res)=>{
 const raw=typeof req.body.url==='string'?req.body.url.trim():'';
 if(!raw || raw.length>2048) return res.status(400).json({error:'Enter a URL under 2048 characters.'});
 let parsed; try{parsed=new URL(raw)}catch{return res.status(400).json({error:'Enter a complete URL such as https://example.com'});}
 if(!['http:','https:'].includes(parsed.protocol)) return res.status(400).json({error:'Only HTTP and HTTPS URLs are supported.'});
 const reasons=[];
 if(parsed.protocol!=='https:') reasons.push('The URL does not use HTTPS.');
 if(parsed.username || parsed.password) reasons.push('The URL contains user-info before the host.');
 if(parsed.hostname.includes('xn--')) reasons.push('The hostname uses internationalized/punycode encoding.');
 if((parsed.hostname.match(/\./g)||[]).length>=4) reasons.push('The hostname has many subdomain levels.');
 if(/@|%|\d{5,}/.test(raw)) reasons.push('The URL contains symbols or long digit sequences worth checking.');
 if(/login|verify|account|secure|update|password/i.test(parsed.pathname+parsed.search)) reasons.push('The path or query includes words often used in lures.');
 res.json({url:raw,risk:reasons.length>=3?'High':reasons.length?'Needs review':'Lower signal',reasons:reasons.length?reasons:['No listed heuristic was triggered.'],warning:'Heuristics can produce false positives and false negatives. Do not enter credentials on a site based only on this result.'});
});
app.listen(PORT,()=>console.log('Phishing URL Detector running at http://localhost:'+PORT));
