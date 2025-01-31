# IP Geolocation MCP Server

This is a simple [Model Context Protocol](https://modelcontextprotocol.io) server that uses the [ipinfo.io](https://ipinfo.io) API to get detailed information about an IP address.
This information can provide information about where the user is located and the network that they are using.

## Installation

You'll need to create a token to use the IPInfo API.
If you don't already have one, you can sign up for a free account at https://ipinfo.io/signup.

```yaml
{
    "ipinfo": {
        "command": "uvx",
        "args": ["--from", "git+https://github.com/briandconnelly/mcp-server-ipinfo.git", "mcp-server-ipinfo"],
        "env": {
            "IPINFO_API_TOKEN": "<YOUR TOKEN HERE>"
        }
    }
}
```

## Components

### Tools

- `get_ip_details`: This tool is used to get detailed information about an IP address.
    - **Input:** `ip`: The IP address to get information about.
    - **Output:** `IPDetails`: A Pydantic model containing detailed information about the IP, including location, organization, and country details.

### Resources   

No custom resources are included

### Prompts

No custom prompts are included


## License

MIT License - See [LICENSE](LICENSE) file for details.

## Disclaimer

This project is not affiliated with [IPInfo](https://ipinfo.io).
