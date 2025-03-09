# IP Geolocation MCP Server
[![smithery badge](https://smithery.ai/badge/@briandconnelly/mcp-server-ipinfo)](https://smithery.ai/server/@briandconnelly/mcp-server-ipinfo)

This is a simple [Model Context Protocol](https://modelcontextprotocol.io) server that uses the [ipinfo.io](https://ipinfo.io) API to get detailed information about an IP address.
This can be used to determine where the user is located (approximately) and what network they are used.

![Example conversation using mcp-server-ipinfo](demo.png)


## Installation

You'll need to create a token to use the IPInfo API.
If you don't already have one, you can sign up for a free account at https://ipinfo.io/signup.

To use with Claude desktop, add the following to the `mcpServers` section of your `claude_desktop_config.json` file:

```yaml
    "ipinfo": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/briandconnelly/mcp-server-ipinfo.git",
        "mcp-server-ipinfo"
      ],
      "env": {
        "IPINFO_API_TOKEN": "<YOUR TOKEN HERE>"
      }
    }
```

### Installing via Smithery

To install IP Geolocation Server for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@briandconnelly/mcp-server-ipinfo):

```bash
npx -y @smithery/cli install @briandconnelly/mcp-server-ipinfo --client claude
```

## Components

### Tools

- `get_ip_details`: This tool is used to get detailed information about an IP address.
    - **Input:** `ip`: The IP address to get information about.
    - **Output:** `IPDetails`: A Pydantic model containing detailed information about the IP, including location, organization, and country details.

### Resources   

_No custom resources are included_

### Prompts

_No custom prompts are included_


## License

MIT License - See [LICENSE](LICENSE) file for details.

## Disclaimer

This project is not affiliated with [IPInfo](https://ipinfo.io).
