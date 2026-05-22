# zo2api

`zo2api` exposes Zo as OpenAI-compatible and Anthropic-compatible HTTP APIs.

## Configuration

Copy `.env.example` to `.env` in the same directory as `server.js`, then edit `.env` and fill in your real token.

Create an Access Token in Zo Computer: go to **Settings -> Advanced -> Access Tokens**, then create a token that starts with `zo_sk_`.

```env
PORT=8000
ZO_ACCESS_TOKEN=XXX
PROXY_API_KEY=sk-proxy
PROXY_PROMPT_OVERRIDE=false
PROXY_OUTPUT_SANITIZE=false
```

### Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PORT` | No | `8000` | Local HTTP server port. |
| `ZO_ACCESS_TOKEN` | Yes | - | Zo access token. Multiple token formats are supported. |
| `Z0_ACCESS_TOKEN` | No | - | Compatibility alias for `ZO_ACCESS_TOKEN` using zero (`0`). `ZO_ACCESS_TOKEN` takes precedence. |
| `PROXY_API_KEY` | No | random `sk-proxy-*` value | Client-facing proxy API key. Set this to a stable value for repeatable access. |
| `PROXY_PROMPT_OVERRIDE` | No | `false` | Enables prompt override behavior when set to `true`. |
| `PROXY_OUTPUT_SANITIZE` | No | `false` | Enables output sanitizing when set to `true`. |

### `ZO_ACCESS_TOKEN` formats

Any of the following formats are accepted:

```env
ZO_ACCESS_TOKEN=XXX
ZO_ACCESS_TOKEN=XXX,yyy,ZZz
ZO_ACCESS_TOKEN=[xxx,yyy,Zzz]
ZO_ACCESS_TOKEN=["XXX","yyy","zZZ"]
ZO_ACCESS_TOKEN=["XXX"，"yyy"，"zZZ"]
```

When multiple tokens are provided, the server randomly selects one token per request.

## Start

```bash
cp .env.example .env
node server.js
```

To manage the service with PM2, run:

```bash
pm2 start server.js --name zo2api
```

If the server starts successfully, it listens on `http://localhost:8000` by default.

## API endpoints

### OpenAI format

```text
POST http://localhost:8000/v1/chat/completions
```

### Anthropic format

```text
POST http://localhost:8000/v1/messages
```

### Model list

```text
GET http://localhost:8000/v1/models
```

## Authentication

Send the configured proxy API key in the `Authorization` request header:

```text
Authorization: Bearer sk-proxy
```
