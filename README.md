# pkge-client

Unofficial Python client for the pkge.net API.

## Installation

```bash
pip install pkge-client
```

## Usage

```python
import asyncio
from pkge import PkgeClient

async def main():
    client = PkgeClient()
    
    # 1. Fetch initial tracking payload
    data = await client.get_tracking_initial("00340434694908615482")
    print(data)
    
    # 2. Trigger an update
    update_res = await client.request_update("00340434694908615482")
    print(update_res)
    
    # 3. Poll for status using the hash from the initial data
    if "hash" in data:
        status_data = await client.get_tracking_status("00340434694908615482", data["hash"])
        print(status_data)
        
    await client.close()

asyncio.run(main())
```
