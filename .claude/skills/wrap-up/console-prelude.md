# Console prelude for "Break it"

Copy this block into the report as its first `js` code block. The reader runs `npm run demo`, opens http://localhost:5173, and pastes it into DevTools → Console once; the experiment blocks after it use its names.

- `Vault`: the class itself, a global the dev demo sets (`demo/main.ts`).
- `vault`: a second connection to the demo's database. Experiments use scopes of their own (`break-…`), so the demo's `demo` scope stays as it was until a `vault.wipe()`, which clears every scope; say so where a block calls it.
- `editKey(scope, id, change)`: rewrites one stored key record with raw IndexedDB, as a storage writer would. DevTools can't edit IndexedDB values. `change` gets the stored record and returns the one to put; a changed `scope` or `id` writes a copy under the new key and leaves the original.
- `outcome(promise)`: `'ok'`, or the error's name, code and message, for printing what a call did.

```js
const vault = await Vault.open();
const editKey = (scope, id, change) =>
  new Promise((resolve, reject) => {
    const open = indexedDB.open('vault');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction('keys', 'readwrite');
      const store = tx.objectStore('keys');
      store.get([scope, id]).onsuccess = (event) => store.put(change(event.target.result));
      tx.oncomplete = () => (db.close(), resolve());
      tx.onerror = () => (db.close(), reject(tx.error));
    };
  });
const outcome = (promise) => promise.then(() => 'ok', (e) => `${e.name} ${e.code ?? ''}: ${e.message}`);
```
