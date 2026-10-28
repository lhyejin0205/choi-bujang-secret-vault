import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (!Number.isInteger(config.step) || config.step < 1 || config.step > 12) {
  throw new Error('aleph.config.json의 단계를 확인하세요.');
}
if (config.step >= 2) {
  for (const path of [resolve(root, 'data.json'), output]) {
    try {
      await access(path);
      throw new Error('2단계 이후에는 data.json이 남아 있으면 안 됩니다. 공개 자료 파일을 제거하세요.');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
} else {
  const source = resolve(root, 'data.json');
  const data = JSON.parse(await readFile(source, 'utf8'));
  if (!Array.isArray(data.notes)) {
    throw new Error('실습용 공개 자료 형식을 확인하세요. 실제 학생 자료를 넣으면 안 됩니다.');
  }
  await mkdir(resolve(root, 'public'), { recursive: true });
  await writeFile(output, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
  console.log('실습용 공개 자료를 public/data.json에 복사했습니다.');
}
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
