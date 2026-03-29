import fs from 'fs';

const code = fs.readFileSync('server.mjs', 'utf8');
let count = 0;
let line = 1;
let column = 0;
let lastErrorLine = null;

for (let i = 0; i < code.length; i++) {
  if (code[i] === '{') count++;
  if (code[i] === '}') count--;
  if (count < 0) {
    console.log(`❌ Unmatched closing brace at line ${line}, column ${column}`);
    count = 0; // reset to continue checking
    lastErrorLine = line;
  }
  if (code[i] === '\n') {
    line++;
    column = 0;
  } else {
    column++;
  }
}

console.log(`\nFinal brace balance: ${count} (should be 0)`);
if (count > 0) {
  console.log(`❌ Missing ${count} closing brace(s).`);
}
