# images

Generates an image through `/v1/images/generations` and writes it to `image-0.png`.

```bash
cd proto && pnpm install && make build-sdk
cd examples/images
ZS_MNEMONIC="word word …" pnpm start --model <image model id> "a lighthouse at dusk"
```

- `ZS_MNEMONIC` is a 25-word Algorand mnemonic for the paying account, holding USDC and ALGO.
- `--network` is `mainnet` (the default) or `testnet`. **On mainnet this spends real USDC.**
- `--size` (default `1024x1024`) and `--out` (default `image`) are passed through.

`discovery` lists the network's models. An image comes back inline (`b64_json`, written to a file)
or as a URL (printed), depending on the node's backend.

A node prices an image request per image, from the size and quality asked for, not per token, so
the ticket's ceiling is known before the image is generated. The reply is not streamed, so it
arrives as one `frame` event carrying the OpenAI images body. Ask for `stream: true` with
`partial_images` and the turn yields `image.progress` and `image.partial` events as the node
produces them, where the model supports it.

`/v1/images/edits` works the same way with a multipart body: pass it as `body` with its
`contentType`.
