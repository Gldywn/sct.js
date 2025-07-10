import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Reads a file from the test/testdata directory.
 * @param fileName The name of the file to read.
 * @returns A Buffer containing the file data.
 */
export function readTestData(fileName: string): Buffer {
  return fs.readFileSync(path.join(__dirname, 'testdata', fileName));
}
