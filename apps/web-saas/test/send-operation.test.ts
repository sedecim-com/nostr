import { describe, expect, it } from 'vitest';
import { fileKey, SendOperation } from '../src/lib/outbox';

// FR011-05 (scope §11.2): the web keeps one operation id while the user retries the same send.
describe('SendOperation', () => {
  it('keeps the id while the same message is retried, and starts a new one when it changes or goes through', () => {
    const op = new SendOperation();
    const first = op.for('["bob","hola",""]');
    expect(first).toMatch(/^[0-9a-f]{32}$/);
    expect(op.for('["bob","hola",""]')).toBe(first); // «Enviar» again after an error
    const edited = op.for('["bob","hola!",""]');
    expect(edited).not.toBe(first); // another text is another message
    op.done();
    expect(op.for('["bob","hola!",""]')).not.toBe(edited); // sent: the same text again is a new message
  });

  it('tells files apart by name, size and modification time', () => {
    expect(fileKey(undefined)).toBe('');
    expect(fileKey({ name: 'a.png', size: 3, lastModified: 1 })).toBe(fileKey({ name: 'a.png', size: 3, lastModified: 1 }));
    expect(fileKey({ name: 'a.png', size: 3, lastModified: 1 })).not.toBe(fileKey({ name: 'a.png', size: 4, lastModified: 1 }));
  });
});
