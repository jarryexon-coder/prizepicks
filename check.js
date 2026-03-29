const fs = require('fs');
const code = fs.readFileSync('server.mjs', 'utf8');
let count = 0;
for (let i = 0; i < code.length; i++) {
  if (code[i] === '{') count++;
  if (code[i] === '}') count--;
  if (count < 0) {
    console.log(`Unmatched closing brace at approximate character ${i}`);
    break;
  }
}
console.log(`Final brace balance: ${count}`);
