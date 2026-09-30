// SPDX-License-Identifier: Apache-2.0
import { componentize } from '@bytecodealliance/componentize-js';
import { writeFile } from 'node:fs/promises';
const [sourcePath, witPath, output] = process.argv.slice(2);
if (!sourcePath || !witPath || !output) throw new Error('source, WIT and output required');
const { component } = await componentize({
  sourcePath, witPath, worldName: 'app', enableAot: false,
  disableFeatures: ['stdio', 'random', 'clocks', 'http', 'fetch-event'],
});
await writeFile(output, component);
