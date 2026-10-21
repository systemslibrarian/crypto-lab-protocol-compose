// Concrete source mutations: baseline, built mutant, named failure, exact restoration.
import {readFileSync,writeFileSync,readdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const cases=[
  {
    "name": "recipient omitted from bound signature",
    "file": "src/signcrypt.ts",
    "anchor": "encode(['exhibit7-bound-v1', message, recipient])",
    "replacement": "encode(['exhibit7-bound-v1', message])",
    "test": "Exhibit 7: bound identities reject strip and forward"
  },
  {
    "name": "inner and outer sender comparison omitted",
    "file": "src/signcrypt.ts",
    "anchor": "const senderMatches = r.innerSender === packet.sender;",
    "replacement": "const senderMatches = true;",
    "test": "Exhibit 7: bound identities reject strip and forward"
  },
  {
    "name": "signature verification falsely reports success",
    "file": "src/signcrypt.ts",
    "anchor": "return await crypto.subtle.verify('Ed25519', key, unhex(signature), data);",
    "replacement": "return true;",
    "test": "Exhibit 7: GCM byte flips and noncanonical S plus L"
  },
  {
    "name": "alarm conclusion painted safe",
    "file": "src/signcrypt-panel.ts",
    "anchor": "${badge(kind, headline)}",
    "replacement": "${badge('safe', headline)}",
    "test": "Exhibit 7: strip is misattributed"
  },
  {
    "name": "negative claim sentence deleted",
    "file": "src/signcrypt-panel.ts",
    "anchor": "export const NEGATIVE = 'A valid signature inside a correctly decrypted message does not establish who the sender meant it for.';",
    "replacement": "export const NEGATIVE = '';",
    "test": "Exhibit 7: forwarded negative fixture"
  },
  {
    "name": "negative fixture signature check broken",
    "file": "src/signcrypt.ts",
    "anchor": "const ok = !!signer && await verify(signer.signing.publicKey, data, signature);",
    "replacement": "const ok = receiver.name !== 'Rita' && !!signer && await verify(signer.signing.publicKey, data, signature);",
    "test": "Exhibit 7: forwarded negative fixture"
  }
];
const run=(command,args,extra={})=>{const r=spawnSync(command,args,{encoding:'utf8',timeout:120000,env:{...process.env,CI:'1',...extra}});return {status:r.status,output:(r.stdout??'')+'\n'+(r.stderr??'')};};
function requirePass(r,label){if(r.status!==0)throw new Error(label+'\n'+r.output);}
function assets(){return Object.fromEntries(readdirSync('dist/assets').filter(f=>f.endsWith('.js')).sort().map(f=>[f,createHash('sha256').update(readFileSync('dist/assets/'+f)).digest('hex')]));}
const hash=()=>createHash('sha256').update(JSON.stringify(assets())).digest('hex');
function owning(e){return e.unit?run('npx',['vitest','run','src/cbcmac/cbcmac.test.ts','-t',e.test]):run('npx',['playwright','test',...(process.env.PLAYWRIGHT_CONFIG?['--config',process.env.PLAYWRIGHT_CONFIG]:[]),'--project=chromium','e2e/claims.spec.ts','--grep',e.test,'--retries=0'],{MUTATION_ASSETS:JSON.stringify(assets())});}
const records=[];
for(const e of cases){
 const source=readFileSync(e.file,'utf8');if(source.split(e.anchor).length!==2)throw new Error(e.name+': ambiguous anchor');
 requirePass(run('npm',['run','build']),e.name+' baseline build');const baseline=hash(),before=owning(e);requirePass(before,e.name+' baseline test');if(!/1 passed/.test(before.output))throw new Error('Owning test did not run exactly once');
 let mutant='',sourceDiff='',failure,restoredGreen=false;
 try{
  writeFileSync(e.file,source.replace(e.anchor,e.replacement));sourceDiff=run('git',['diff','--',e.file]).output.trim();if(!sourceDiff)throw new Error('No source patch');
  requirePass(run('npm',['run','build']),e.name+' mutant build');mutant=hash();if(mutant===baseline)throw new Error('Mutation did not change build');failure=owning(e);
 }finally{
  writeFileSync(e.file,source);requirePass(run('npm',['run','build']),e.name+' restore build');if(hash()!==baseline)throw new Error('Build not byte-exact restored');
  const restored=owning(e);requirePass(restored,e.name+' restored test');restoredGreen=/1 passed/.test(restored.output);
 }
 const assertionFailure=failure.status!==0&&/AssertionError|Error: expect\(|expect\(received\)|expect\(locator\)\.[A-Za-z]+\(expected\) failed/.test(failure.output)&&failure.output.includes(e.test)&&!failure.output.includes('MUTATION_ASSET_MISMATCH')&&!failure.output.includes('Process from config.webServer');
 if(!assertionFailure||!restoredGreen)throw new Error(e.name+' did not fail a named assertion\n'+failure.output);
 records.push({name:e.name,sourceDiff,baseline,mutant,owningTest:e.test,unit:!!e.unit,baselinePassed:true,mutantBuilt:true,assertionFailure,retries:0,servedAssetGuard:!e.unit,restoredGreen,restoredHash:hash(),failureEvidence:failure.output.slice(0,4500)});
 console.log(e.name+': killed; exact build restored; owning test green');
}
writeFileSync('mutation-evidence.json',JSON.stringify(records,null,2)+'\n');
