// Both builds emit .js files. These markers tell Node which module system
// each folder uses, so `import` gets ESM and `require` gets CommonJS.
import { writeFileSync } from "node:fs";

writeFileSync("dist/esm/package.json", JSON.stringify({ type: "module" }) + "\n");
writeFileSync("dist/cjs/package.json", JSON.stringify({ type: "commonjs" }) + "\n");
