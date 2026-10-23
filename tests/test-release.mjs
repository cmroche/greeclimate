import assert from 'node:assert/strict';
import test from 'node:test';
import { cosmiconfig } from 'cosmiconfig';
import { analyzeCommits } from '@semantic-release/commit-analyzer';
import { generateNotes } from '@semantic-release/release-notes-generator';

const { config } = await cosmiconfig('release').search();
const pluginOptions = (name) => config.plugins.find((plugin) => plugin[0] === name)[1];
const analyzer = pluginOptions('@semantic-release/commit-analyzer');
const generator = pluginOptions('@semantic-release/release-notes-generator');

for (const [message, release, section, description] of [
  ['refactor!: separate device families', 'major', 'BREAKING CHANGES', 'separate device families'],
  ['refactor(device)!: match firmware codes', 'major', 'BREAKING CHANGES', 'match firmware codes'],
  ['fix: migrate controls\n\nBREAKING CHANGE: Use typed devices.', 'major', 'BREAKING CHANGES', 'Use typed devices.'],
  ['feat(device): expose capabilities', 'minor', 'Features', 'expose capabilities'],
  ['fix(device): preserve state', 'patch', 'Bug Fixes', 'preserve state'],
  ['refactor(device): simplify internals', null, null, null],
]) {
  test(message.split('\n')[0], async () => {
    const context = {
      cwd: process.cwd(),
      commits: [{ hash: '123456789abcdef', message }],
      logger: { log() {} },
      options: { repositoryUrl: 'https://github.com/cmroche/greeclimate.git' },
      lastRelease: { gitTag: 'v3.7.0' },
      nextRelease: { version: '4.0.0', gitTag: 'v4.0.0' },
    };
    assert.equal(await analyzeCommits(analyzer, context), release);
    const notes = await generateNotes(generator, context);
    if (section) {
      assert.ok(notes.includes(section), notes);
      assert.ok(notes.includes(description), notes);
    } else {
      assert.ok(!notes.includes('simplify internals'), notes);
    }
  });
}
