# reconcile

A ticket journal that outlives the process, and a Client that finishes what an earlier one left
open.

Each paid turn writes its ticket to `Stores.journal` when escrow opens, records the node's receipt
before settling, and removes the row once the settle is confirmed. A crash between the open and the
settle leaves the row behind. A Client given that journal sweeps it when it starts and then every
minute. For each ticket it does one of these:

- re-sends the payer's settle, if the receipt was recorded but the settle never landed and the
  ticket is still inside its settlement window;
- refunds the ticket (`refundInactive`) once its deadline has passed with no claim filed, even if
  the payer recorded a receipt;
- calls `settleLapsed` on a node's claim the node didn't finish itself;
- forgets the ticket once it is settled, refunded or frozen on chain.

The default journal (`memoryJournal()`) dies with the process, so the tickets in it can only be
refunded by hand. Every long-lived payer should pass a durable `TicketJournal`. This example writes
one over a JSON file (`fileJournal` in `index.ts`): each change is synced to disk before it replaces
the file, and a lock file keeps a second process out.

```bash
cd proto && pnpm install && make build-sdk
cd examples/reconcile
ZS_MNEMONIC="word word …" pnpm start              # sweeps ./journal.json until it's empty
```

- Use the same `--journal` file every time you pay from the account, from **one process at a
  time**. Two holders would overwrite each other's rows, and both sweeps would submit the same
  refund. `Client.create` catches two Clients on one journal object in the same process, but not
  two processes on one file, which is what the lock is for. A crash leaves `journal.json.lock`
  behind: delete it once no process is using the journal.
- The sweep logs each action through the logger. Ticket ids, transaction ids and amounts appear
  there; prompts and answers never do.
- A ticket whose submits keep failing is given up on for the rest of the process and stays in the
  journal, so the example then runs until Ctrl-C.
- `--network` is `mainnet` (the default) or `testnet`. A refund or settle costs the payer an
  Algorand transaction fee.

To journal real turns, copy `fileJournal` into the program that pays and pass its journal as
`stores: { journal }` to that program's Client. Run that program or this one, not both at once.
